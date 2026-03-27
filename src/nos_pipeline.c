#include "nos.h"
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_ether.h>
#include <rte_jhash.h>
#include <rte_lpm.h>
#include <rte_prefetch.h>
#include <rte_cycles.h>
#include <string.h>

/* ============================================================
   SESSION LOOKUP / CREATE
   ============================================================
   This is the hot path. Every packet hits this function.
   Design mirrors NOS: session is pinned to one worker core
   via RSS hash — no locking needed on the common path.
   ============================================================ */

nos_session_t *
nos_session_lookup_or_create(nos_session_key_t *key, nos_lcore_ctx_t *ctx)
{
    int32_t pos = rte_hash_lookup(g_nos.session_table, key);

    if (likely(pos >= 0)) {
        /* fast path: existing session */
        nos_session_t *sess = &g_nos.session_data[pos];
        sess->last_seen_tsc = rte_rdtsc();
        sess->pkt_count++;
        return sess;
    }

    /* slow path: new session — create entry */
    pos = rte_hash_add_key(g_nos.session_table, key);
    if (unlikely(pos < 0)) {
        /* table full — drop */
        rte_atomic64_inc(&ctx->pkts_dropped);
        return NULL;
    }

    nos_session_t *sess = &g_nos.session_data[pos];
    memset(sess, 0, sizeof(*sess));
    sess->key           = *key;
    sess->state         = NOS_SESSION_NEW;
    sess->app_id        = APP_UNKNOWN;
    sess->last_seen_tsc = rte_rdtsc();
    sess->pkt_count     = 1;

    /* default WAN path selection — SLA-based selection happens below */
    sess->wan_path = nos_select_wan_path(sess);

    rte_atomic64_inc(&ctx->sessions_created);
    return sess;
}

/* ============================================================
   L3/L4 HEADER EXTRACTION
   Returns pointer to IP header; fills key. Returns NULL if
   not IPv4 or malformed.
   ============================================================ */

static inline struct rte_ipv4_hdr *
extract_key(struct rte_mbuf *pkt, nos_session_key_t *key)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    if (unlikely(rte_be_to_cpu_16(eth->ether_type) != RTE_ETHER_TYPE_IPV4))
        return NULL;

    struct rte_ipv4_hdr *ip =
        (struct rte_ipv4_hdr *)((uint8_t *)eth + sizeof(*eth));

    /* bounds check */
    if (unlikely((uint8_t *)ip + sizeof(*ip) >
                 rte_pktmbuf_mtod(pkt, uint8_t *) + pkt->data_len))
        return NULL;

    key->src_ip   = ip->src_addr;
    key->dst_ip   = ip->dst_addr;
    key->proto    = ip->next_proto_id;
    key->src_port = 0;
    key->dst_port = 0;
    memset(key->pad, 0, sizeof(key->pad));

    uint8_t ihl = (ip->version_ihl & 0x0f) << 2;
    void *l4 = (uint8_t *)ip + ihl;

    if (key->proto == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = l4;
        if (likely((uint8_t *)tcp + sizeof(*tcp) <=
                   rte_pktmbuf_mtod(pkt, uint8_t *) + pkt->data_len)) {
            key->src_port = tcp->src_port;
            key->dst_port = tcp->dst_port;
        }
    } else if (key->proto == IPPROTO_UDP) {
        struct rte_udp_hdr *udp = l4;
        if (likely((uint8_t *)udp + sizeof(*udp) <=
                   rte_pktmbuf_mtod(pkt, uint8_t *) + pkt->data_len)) {
            key->src_port = udp->src_port;
            key->dst_port = udp->dst_port;
        }
    }

    return ip;
}

/* ============================================================
   APPLICATION IDENTIFICATION (APPID / DPI — stub)

   Real NOS runs signatures over 3800+ apps. Here we implement
   the same structural pattern: first-packet classification,
   then offload. The classifiers below are port-based (simplest
   form); a real implementation adds:
     - payload inspection (nDPI integration or custom engine)
     - TLS SNI extraction for HTTPS
     - DNS response caching for cloud app IP → AppID mapping
     - flow behavioral heuristics
   ============================================================ */

int nos_classify_app(struct rte_mbuf *pkt __rte_unused, nos_session_t *sess)
{
    if (sess->state == NOS_SESSION_OFFLOADED)
        return 0;   /* already classified — skip */

    uint16_t dport = rte_be_to_cpu_16(sess->key.dst_port);
    uint16_t sport = rte_be_to_cpu_16(sess->key.src_port);

    /* L4 port-based AppID (first-pass) */
    nos_app_id_t app = APP_UNKNOWN;

    if (sess->key.proto == IPPROTO_UDP && dport == 4500)
        app = APP_IPSEC_ESP;  /* NAT-T IPSec */
    else if (sess->key.proto == IPPROTO_ESP)
        app = APP_IPSEC_ESP;
    else if (dport == 53 || sport == 53)
        app = APP_DNS;
    else if (dport == 80 || sport == 80)
        app = APP_HTTP;
    else if (dport == 443 || sport == 443)
        app = APP_HTTPS;
    else if (dport == 5060 || dport == 5061)
        app = APP_VOIP;
    else if (dport == 554 || dport == 1935 || dport == 8554)
        app = APP_STREAMING;
    else
        app = APP_BULK;

    sess->app_id = app;

    /* QoS class assignment:
       VoIP → class 0 (strict priority)
       HTTPS/streaming → class 4
       HTTP → class 8
       Bulk → class 12 */
    switch (app) {
    case APP_VOIP:      sess->qos_class = 0;  break;
    case APP_HTTPS:     sess->qos_class = 4;  break;
    case APP_STREAMING: sess->qos_class = 4;  break;
    case APP_HTTP:      sess->qos_class = 8;  break;
    default:            sess->qos_class = 12; break;
    }

    /* After N packets, offload the session — bypass DPI on subsequent pkts.
       NOS calls this "application offload"; saves CPU cycles for
       classified, trusted flows. */
    if (sess->pkt_count >= 5 && sess->app_id != APP_UNKNOWN) {
        sess->state = NOS_SESSION_OFFLOADED;
    } else {
        sess->state = NOS_SESSION_ACTIVE;
    }

    return 0;
}

/* ============================================================
   WAN PATH SELECTION
   NOS selects the WAN path per-session based on:
     - Application SLA requirements
     - Real-time link quality (loss, latency, jitter)
     - Configured policy (prefer MPLS for VoIP, etc.)
   Here we implement the selection logic; BFD probing that
   updates wan[i].loss_ppm / rtt_us lives in the control thread.
   ============================================================ */

int nos_select_wan_path(nos_session_t *sess)
{
    if (g_nos.n_wan == 0) return 0;

    /* Find first active circuit as baseline — avoids comparing
       against an inactive circuit if best=0 is down. */
    uint8_t best = 255;
    for (uint8_t i = 0; i < g_nos.n_wan; i++) {
        if (g_nos.wan[i].active) { best = i; break; }
    }
    if (best == 255) return 0;   /* all circuits down: fail safe to 0 */
    if (g_nos.n_wan == 1) return best;

    for (uint8_t i = best + 1; i < g_nos.n_wan; i++) {
        nos_wan_circuit_t *c = &g_nos.wan[i];
        if (!c->active) continue;

        /* VoIP: strictly prefer lowest RTT on <0.1% loss circuits */
        if (sess->app_id == APP_VOIP) {
            if (c->loss_ppm < 1000 &&
                (g_nos.wan[best].loss_ppm >= 1000 ||
                 c->rtt_us < g_nos.wan[best].rtt_us))
                best = i;
            continue;
        }

        /* General: composite score = RTT + loss_penalty */
        uint32_t score_best = g_nos.wan[best].rtt_us +
                              g_nos.wan[best].loss_ppm / 100;
        uint32_t score_i    = c->rtt_us + c->loss_ppm / 100;
        if (score_i < score_best)
            best = i;
    }

    return best;
}

/* ============================================================
   NAPT (Network Address and Port Translation)
   Simplified stateful NAPT. In NOS this handles:
     - Static NAT, dynamic NAT, NAPT, destination NAT
     - Inter-tenant NAT, ALG support (SIP, FTP)
   ============================================================ */

int nos_nat_translate(struct rte_mbuf *pkt, nos_session_t *sess)
{
    /* only translate sessions destined for WAN */
    if (sess->app_id == APP_IPSEC_ESP) return 0;

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    struct rte_ipv4_hdr  *ip  = (struct rte_ipv4_hdr *)(eth + 1);

    nos_nat_key_t nk = {
        .orig_src_ip   = ip->src_addr,
        .orig_src_port = sess->key.src_port,
    };

    int32_t pos = rte_hash_lookup(g_nos.nat_table, &nk);
    if (pos >= 0) {
        nos_nat_entry_t *ne = &g_nos.nat_data[pos];
        if (ne->active) {
            /* rewrite src IP + port */
            ip->src_addr = ne->xlat_src_ip;
            if (sess->key.proto == IPPROTO_TCP) {
                struct rte_tcp_hdr *tcp =
                    (struct rte_tcp_hdr *)((uint8_t *)ip +
                     ((ip->version_ihl & 0x0f) << 2));
                tcp->src_port = ne->xlat_src_port;
            } else if (sess->key.proto == IPPROTO_UDP) {
                struct rte_udp_hdr *udp =
                    (struct rte_udp_hdr *)((uint8_t *)ip +
                     ((ip->version_ihl & 0x0f) << 2));
                udp->src_port = ne->xlat_src_port;
            }
            /* mark mbuf for hardware checksum recalculation */
            pkt->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
        }
    }
    return 0;
}

/* ============================================================
   L3 FORWARDING
   LPM lookup → next-hop port → TX ring
   ============================================================ */

int nos_forward(struct rte_mbuf *pkt, nos_session_t *sess,
                nos_lcore_ctx_t *ctx)
{
    uint32_t dst_ip  = rte_be_to_cpu_32(sess->key.dst_ip);
    uint32_t next_hop = 0;

    /* LPM lookup */
    if (rte_lpm_lookup(g_nos.lpm_v4, dst_ip, &next_hop) != 0)
        next_hop = 0;   /* default route */

    /* for WAN-bound traffic, use the SLA-selected path */
    if (next_hop == 0 && g_nos.n_wan > 0)
        next_hop = sess->wan_path;

    pkt->port = (uint16_t)next_hop;

    /* enqueue to worker→poller TX ring */
    if (rte_ring_enqueue(g_nos.worker_to_poller, pkt) != 0) {
        rte_pktmbuf_free(pkt);
        rte_atomic64_inc(&ctx->pkts_dropped);
        return -1;
    }

    rte_atomic64_inc(&ctx->pkts_tx);
    return 0;
}

/* ============================================================
   MAIN BURST PROCESSING PIPELINE
   This is NOS's single-pass architecture:
   one packet traverses every stage exactly once —
   session lookup → AppID → NAT → path selection → forward
   Metadata produced by each stage is carried on the session
   struct (not re-parsed), mirroring NOS's metadata pipeline.
   ============================================================ */

void nos_process_burst(struct rte_mbuf **pkts, uint16_t n,
                       nos_lcore_ctx_t *ctx)
{
    /* prefetch: load next packet's headers into L1 cache while
       we process the current one — DPDK standard technique */
    for (uint16_t i = 0; i < n; i++) {
        if (i + 1 < n)
            rte_prefetch0(rte_pktmbuf_mtod(pkts[i + 1], void *));

        struct rte_mbuf   *pkt = pkts[i];
        nos_session_key_t  key;

        /* --- L3/L4 header parse --- */
        struct rte_ipv4_hdr *ip = extract_key(pkt, &key);
        if (unlikely(!ip)) {
            rte_pktmbuf_free(pkt);
            rte_atomic64_inc(&ctx->pkts_dropped);
            continue;
        }

        pkt->l2_len = sizeof(struct rte_ether_hdr);
        pkt->l3_len = (ip->version_ihl & 0x0f) << 2;

        /* --- session lookup / create (hot path) --- */
        nos_session_t *sess = nos_session_lookup_or_create(&key, ctx);
        if (unlikely(!sess)) {
            rte_pktmbuf_free(pkt);
            continue;
        }

        /* update byte counter */
        sess->byte_count += pkt->pkt_len;

        /* --- single-pass pipeline --- */

        /* stage 1: AppID / DPI
           offloaded sessions skip this stage entirely */
        if (sess->state != NOS_SESSION_OFFLOADED)
            nos_classify_app(pkt, sess);

        /* stage 2: re-select WAN path if metrics changed
           (done lazily every 64 packets per session) */
        if ((sess->pkt_count & 63) == 0)
            sess->wan_path = nos_select_wan_path(sess);

        /* stage 3: NAT rewrite */
        nos_nat_translate(pkt, sess);

        /* stage 4: IPSec (if tunnel SA exists for this dst) */
        uint32_t dst_key = key.dst_ip;
        int32_t sa_pos = rte_hash_lookup(g_nos.ipsec_sa_table, &dst_key);
        if (sa_pos >= 0 && g_nos.ipsec_sa[sa_pos].active) {
            nos_ipsec_encrypt(pkt, &g_nos.ipsec_sa[sa_pos]);
        }

        /* stage 5: L3 forward to TX ring */
        nos_forward(pkt, sess, ctx);
    }
}
