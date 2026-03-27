/*
 * NOS Logic Tests — validates core algorithms without DPDK EAL
 * Tests: session hash semantics, AppID classification,
 *        LPM longest-prefix-match, WAN path selection,
 *        AES-256-GCM encrypt/decrypt pipeline integration
 */
#include <intel-ipsec-mb.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <arpa/inet.h>

/* ---- minimal replicas of NOS types (no DPDK headers needed) ---- */
#define NOS_SESSION_MAX   (1 << 16)
#define NOS_APP_UNKNOWN   0
#define NOS_APP_HTTP      1
#define NOS_APP_HTTPS     2
#define NOS_APP_DNS       3
#define NOS_APP_IPSEC     4
#define NOS_APP_VOIP      5
#define NOS_APP_STREAM    6
#define NOS_APP_BULK      7

#define NOS_SESS_NEW       0
#define NOS_SESS_ACTIVE    1
#define NOS_SESS_OFFLOADED 2

typedef struct __attribute__((packed)) {
    uint32_t src_ip, dst_ip;
    uint16_t sport, dport;
    uint8_t  proto, pad[3];
} sess_key_t;

typedef struct {
    sess_key_t key;
    uint8_t  state, app_id, qos_class, wan_path;
    uint32_t pkt_count;
    uint64_t byte_count;
} session_t;

typedef struct {
    uint32_t ip, mask;
    uint8_t  next_hop;
    bool     valid;
} fib_entry_t;

typedef struct {
    uint32_t rtt_us, loss_ppm;
    bool     active;
} wan_t;

/* ---- test framework ---- */
static int g_pass = 0, g_fail = 0;
#define PASS(msg) do { printf("  PASS: %s\n", msg); g_pass++; } while(0)
#define FAIL(msg) do { printf("  FAIL: %s\n", msg); g_fail++; } while(0)
#define CHECK(c, msg) do { if(c) PASS(msg); else FAIL(msg); } while(0)

/* ---- Session table (open-address hash, FNV-1a) ---- */
static session_t g_sessions[NOS_SESSION_MAX];
static bool      g_sess_used[NOS_SESSION_MAX];

static uint32_t sess_hash(const sess_key_t *k) {
    uint32_t h = 2166136261u;
    const uint8_t *p = (const uint8_t *)k;
    for (size_t i = 0; i < sizeof(sess_key_t) - 3; i++) {
        h ^= p[i]; h *= 16777619u;
    }
    return h % NOS_SESSION_MAX;
}

static session_t *sess_lookup_or_create(const sess_key_t *k) {
    uint32_t idx = sess_hash(k);
    uint32_t probe = idx;
    /* linear probe */
    for (uint32_t i = 0; i < 32; i++) {
        uint32_t j = (probe + i) % NOS_SESSION_MAX;
        if (!g_sess_used[j]) {
            g_sess_used[j] = true;
            g_sessions[j].key = *k;
            g_sessions[j].state = NOS_SESS_NEW;
            g_sessions[j].pkt_count = 1;
            return &g_sessions[j];
        }
        if (memcmp(&g_sessions[j].key, k, sizeof(sess_key_t)) == 0) {
            g_sessions[j].pkt_count++;
            return &g_sessions[j];
        }
    }
    return NULL;
}

/* ---- AppID classification ---- */
static void classify(session_t *s) {
    if (s->state == NOS_SESS_OFFLOADED) return;
    uint16_t dp = ntohs(s->key.dport), sp = ntohs(s->key.sport);
    uint8_t proto = s->key.proto;

    if (proto == 50 || (proto == 17 && dp == 4500)) s->app_id = NOS_APP_IPSEC;
    else if (dp == 53 || sp == 53)  s->app_id = NOS_APP_DNS;
    else if (dp == 80 || sp == 80)  s->app_id = NOS_APP_HTTP;
    else if (dp == 443)             s->app_id = NOS_APP_HTTPS;
    else if (dp == 5060 || dp == 5061) s->app_id = NOS_APP_VOIP;
    else if (dp == 554 || dp == 1935)  s->app_id = NOS_APP_STREAM;
    else                            s->app_id = NOS_APP_BULK;

    switch (s->app_id) {
    case NOS_APP_VOIP:   s->qos_class = 0; break;
    case NOS_APP_HTTPS:  s->qos_class = 4; break;
    case NOS_APP_STREAM: s->qos_class = 4; break;
    case NOS_APP_HTTP:   s->qos_class = 8; break;
    default:             s->qos_class = 12; break;
    }

    if (s->pkt_count >= 5 && s->app_id != NOS_APP_UNKNOWN)
        s->state = NOS_SESS_OFFLOADED;
    else
        s->state = NOS_SESS_ACTIVE;
}

/* ---- LPM (binary search sorted table) ---- */
#define FIB_MAX 64
static fib_entry_t g_fib[FIB_MAX];
static int g_fib_n = 0;

static void fib_add(uint32_t net, uint8_t plen, uint8_t nh) {
    if (g_fib_n >= FIB_MAX) return;
    g_fib[g_fib_n].ip       = net;
    g_fib[g_fib_n].mask     = plen ? (~0u << (32 - plen)) : 0;
    g_fib[g_fib_n].next_hop = nh;
    g_fib[g_fib_n].valid    = true;
    g_fib_n++;
}

static int fib_lookup(uint32_t dst) {
    int best = -1; uint32_t best_mask = 0;
    for (int i = 0; i < g_fib_n; i++) {
        if ((dst & g_fib[i].mask) == (g_fib[i].ip & g_fib[i].mask)) {
            if (g_fib[i].mask >= best_mask) {
                best_mask = g_fib[i].mask;
                best = g_fib[i].next_hop;
            }
        }
    }
    return best;
}

/* ---- WAN path selection ---- */
static uint8_t select_wan(session_t *s, wan_t *wan, int nwan) {
    /* find first active circuit as baseline */
    uint8_t best = 255;
    for (int i = 0; i < nwan; i++)
        if (wan[i].active) { best = i; break; }
    if (best == 255) return 0;

    for (int i = (int)best + 1; i < nwan; i++) {
        if (!wan[i].active) continue;
        if (s->app_id == NOS_APP_VOIP) {
            if (wan[i].loss_ppm < 1000 &&
                (wan[best].loss_ppm >= 1000 ||
                 wan[i].rtt_us < wan[best].rtt_us))
                best = i;
        } else {
            uint32_t si = wan[i].rtt_us + wan[i].loss_ppm / 100;
            uint32_t sb = wan[best].rtt_us + wan[best].loss_ppm / 100;
            if (si < sb) best = i;
        }
    }
    return best;
}

/* ===== TESTS ===== */

static void test_session_table(void) {
    printf("\n--- Test: Session table ---\n");
    memset(g_sessions, 0, sizeof(g_sessions));
    memset(g_sess_used, 0, sizeof(g_sess_used));

    sess_key_t k1 = {
        .src_ip = htonl(0x0a000001), .dst_ip = htonl(0x08080808),
        .sport  = htons(54321),      .dport  = htons(443),
        .proto  = 6 /* TCP */
    };
    session_t *s1 = sess_lookup_or_create(&k1);
    CHECK(s1 != NULL,           "session created on first lookup");
    CHECK(s1->state == NOS_SESS_NEW, "state = NEW");
    CHECK(s1->pkt_count == 1,   "first packet counted");

    session_t *s2 = sess_lookup_or_create(&k1);
    CHECK(s2 == s1,             "second lookup returns same session");
    CHECK(s2->pkt_count == 2,   "packet counter incremented");

    sess_key_t k2 = k1; k2.sport = htons(54322);
    session_t *s3 = sess_lookup_or_create(&k2);
    CHECK(s3 != s1,             "different 5-tuple → different session");
}

static void test_appid(void) {
    printf("\n--- Test: AppID classification ---\n");

    /* HTTPS */
    sess_key_t k = {
        .src_ip=htonl(0xc0a80164), .dst_ip=htonl(0x8e50504e),
        .sport=htons(55000), .dport=htons(443), .proto=6
    };
    session_t s = {.key=k, .pkt_count=1};
    classify(&s);
    CHECK(s.app_id == NOS_APP_HTTPS, "port 443 → HTTPS");
    CHECK(s.qos_class == 4,          "HTTPS QoS class = 4");

    /* VoIP */
    s.key.dport = htons(5060); s.app_id = 0; s.pkt_count = 1;
    classify(&s);
    CHECK(s.app_id == NOS_APP_VOIP,  "port 5060 → VoIP");
    CHECK(s.qos_class == 0,          "VoIP QoS class = 0 (highest priority)");

    /* DNS */
    s.key.dport = htons(53); s.key.proto = 17; s.app_id = 0; s.pkt_count = 1;
    classify(&s);
    CHECK(s.app_id == NOS_APP_DNS,   "port 53 → DNS");

    /* IPSec ESP */
    s.key.proto = 50; s.app_id = 0; s.pkt_count = 1;
    classify(&s);
    CHECK(s.app_id == NOS_APP_IPSEC, "proto 50 → IPSec ESP");

    /* offload after 5 packets */
    s.key.proto = 6; s.key.dport = htons(80);
    s.app_id = 0; s.state = NOS_SESS_NEW;
    for (int i = 1; i <= 6; i++) {
        s.pkt_count = i;
        classify(&s);
    }
    CHECK(s.state == NOS_SESS_OFFLOADED,
          "session offloaded after 5 classified packets");
    CHECK(s.app_id == NOS_APP_HTTP,  "HTTP identified");
}

static void test_fib(void) {
    printf("\n--- Test: LPM FIB ---\n");
    g_fib_n = 0;
    fib_add(0x00000000, 0,  0); /* 0.0.0.0/0  → port 0 (default) */
    fib_add(0x0a000000, 8,  1); /* 10.0.0.0/8 → port 1 (LAN)    */
    fib_add(0xac100000, 12, 2); /* 172.16.0.0/12 → port 2        */

    int nh;
    nh = fib_lookup(0x08080808); CHECK(nh == 0, "8.8.8.8 → default route port 0");
    nh = fib_lookup(0x0a010203); CHECK(nh == 1, "10.1.2.3 → LAN port 1");
    nh = fib_lookup(0xac110001); CHECK(nh == 2, "172.17.0.1 → port 2 (172.16/12)");

    /* more-specific wins */
    fib_add(0x08080800, 24, 3);
    nh = fib_lookup(0x08080808); CHECK(nh == 3, "8.8.8.8 → /24 beats /0");
    nh = fib_lookup(0x08080408); CHECK(nh == 0, "8.8.4.8 → default (not in /24)");
}

static void test_wan_selection(void) {
    printf("\n--- Test: WAN path selection ---\n");
    wan_t wan[3] = {
        {.rtt_us=5000,  .loss_ppm=0,    .active=true},   /* 0: fast  */
        {.rtt_us=50000, .loss_ppm=0,    .active=true},   /* 1: slow  */
        {.rtt_us=8000,  .loss_ppm=5000, .active=true},   /* 2: lossy */
    };
    session_t s = {0};

    /* bulk → lowest RTT */
    s.app_id = NOS_APP_BULK;
    CHECK(select_wan(&s, wan, 3) == 0, "bulk: lowest RTT wins (port 0)");

    /* flip RTTs: wan[0] now slow. wan[2] has rtt=8000 + loss_penalty=50
       = score 8050, which beats wan[1]=50000. Expect port 2. */
    wan[0].rtt_us = 100000;
    CHECK(select_wan(&s, wan, 3) == 2, "bulk: port 2 lowest composite score");
    wan[0].rtt_us = 5000; /* restore */

    /* VoIP: low loss strict, prefers port 0 over 2 */
    s.app_id = NOS_APP_VOIP;
    wan[0].loss_ppm = 50;   /* <1000 ppm threshold */
    wan[1].loss_ppm = 50;
    CHECK(select_wan(&s, wan, 3) == 0, "VoIP: lower RTT + acceptable loss");

    /* mark best circuit down: wan[0] inactive.
       VoIP needs loss<1000ppm. wan[1]: loss=50ppm ✓. wan[2]: loss=5000ppm ✗.
       Expected winner: wan[1] */
    wan[0].active = false;
    uint8_t path = select_wan(&s, wan, 3);
    CHECK(path == 1, "VoIP: circuit 0 down → wan[1] selected (low loss)");

    /* all down → stays on last active */
    wan[0].active = true; /* restore */
    wan[1].active = false;
    wan[2].active = false;
    CHECK(select_wan(&s, wan, 3) == 0, "only circuit 0 active → selects 0");
    wan[1].active = true; wan[2].active = true; /* restore */
}

static void test_crypto_pipeline(void) {
    printf("\n--- Test: AES-256-GCM pipeline (ESP-style) ---\n");

    IMB_MGR *mgr = alloc_mb_mgr(0);
    if (!mgr) { FAIL("alloc_mb_mgr"); return; }
    IMB_ARCH arch;
    init_mb_mgr_auto(mgr, &arch);

    const char *anames[] = {"NONE","NOAESNI","SSE","AVX","AVX2","AVX512"};
    printf("  ISA: %s\n", arch < IMB_ARCH_NUM ? anames[arch] : "?");

    /* simulate NOS IPSec SA install: expand key once */
    uint8_t key[32]; for (int i=0;i<32;i++) key[i]=i;
    struct gcm_key_data exp;
    IMB_AES256_GCM_PRE(mgr, key, &exp);

    /* simulate NOS tunnel packet:
       [ESP hdr: SPI(4) + Seq(4)] [IV(12)] [payload] [GCM tag(16)] */
    const char *payload = "Branch site traffic: SaaS application flow data.";
    uint32_t plen = strlen(payload);

    uint8_t iv[12]   = {0}; /* in production: 4-byte salt + 8-byte seq */
    uint64_t seq = __builtin_bswap64(42);
    memcpy(iv + 4, &seq, 8);

    /* AAD = ESP header (SPI + seq) — authenticated but not encrypted */
    uint8_t aad[8] = {0xDE,0xAD,0xBE,0xEF, 0x00,0x00,0x00,0x2A};

    uint8_t ct[128]={0}, tag[16]={0}, pt_out[128]={0}, vtag[16]={0};
    struct gcm_context_data ctx;

    IMB_AES256_GCM_ENC(mgr, &exp, &ctx, ct, (uint8_t*)payload, plen,
                        iv, aad, 8, tag, 16);

    CHECK(memcmp(ct, payload, plen) != 0, "ESP payload encrypted");

    IMB_AES256_GCM_DEC(mgr, &exp, &ctx, pt_out, ct, plen,
                        iv, aad, 8, vtag, 16);

    CHECK(memcmp(pt_out, payload, plen) == 0, "ESP payload decrypted correctly");
    CHECK(memcmp(tag, vtag, 16) == 0,         "GCM tag verifies (ESP integrity)");

    /* simulate anti-replay: replay with same seq — tag should still verify
       (replay detected by seq number check in real NOS, not by crypto) */
    uint8_t pt2[128]={0}, vtag2[16]={0};
    IMB_AES256_GCM_DEC(mgr, &exp, &ctx, pt2, ct, plen, iv, aad, 8, vtag2, 16);
    CHECK(memcmp(vtag2, tag, 16) == 0, "replay packet: crypto still valid "
                                        "(seq window check is separate)");

    /* simulate IKE-less SA rekey: new key, new SA slot */
    uint8_t key2[32]; for (int i=0;i<32;i++) key2[i]=i^0xFF;
    struct gcm_key_data exp2;
    IMB_AES256_GCM_PRE(mgr, key2, &exp2);

    uint8_t ct2[128]={0}, tag2[16]={0};
    IMB_AES256_GCM_ENC(mgr, &exp2, &ctx, ct2, (uint8_t*)payload, plen,
                        iv, aad, 8, tag2, 16);

    CHECK(memcmp(ct, ct2, plen) != 0,
          "different SA key → different ciphertext");
    CHECK(memcmp(tag, tag2, 16) != 0,
          "different SA key → different GCM tag");

    /* wrong key decrypt should fail tag verification */
    uint8_t pt_bad[128]={0}, tag_bad[16]={0};
    IMB_AES256_GCM_DEC(mgr, &exp, &ctx, pt_bad, ct2, plen,
                        iv, aad, 8, tag_bad, 16);
    CHECK(memcmp(tag_bad, tag2, 16) != 0,
          "wrong SA key: tag mismatch → packet dropped");

    free_mb_mgr(mgr);
}

static void test_nat_logic(void) {
    printf("\n--- Test: NAT table semantics ---\n");

    /* simplified NAT: flat array keyed by (src_ip, src_port) */
    typedef struct { uint32_t orig_ip; uint16_t orig_port; } nat_key_t;
    typedef struct { uint32_t xlat_ip; uint16_t xlat_port; bool active; } nat_val_t;

    #define NAT_SIZE 16
    nat_key_t nkeys[NAT_SIZE] = {0};
    nat_val_t nvals[NAT_SIZE] = {0};
    int nat_n = 0;

    /* install mapping: 10.1.1.100:50000 → 203.0.113.1:10001 */
    nkeys[nat_n] = (nat_key_t){htonl(0x0a010164), htons(50000)};
    nvals[nat_n] = (nat_val_t){htonl(0xcb007101), htons(10001), true};
    nat_n++;

    /* lookup */
    nat_key_t qk = {htonl(0x0a010164), htons(50000)};
    nat_val_t *found = NULL;
    for (int i=0; i<nat_n; i++)
        if (memcmp(&nkeys[i], &qk, sizeof(nat_key_t)) == 0)
            { found = &nvals[i]; break; }

    CHECK(found != NULL,             "NAT entry found");
    CHECK(found->xlat_port == htons(10001), "translated port correct");
    CHECK(ntohl(found->xlat_ip) == 0xcb007101, "translated IP correct");

    /* miss */
    nat_key_t qk2 = {htonl(0x0a010165), htons(50000)};
    nat_val_t *miss = NULL;
    for (int i=0; i<nat_n; i++)
        if (memcmp(&nkeys[i], &qk2, sizeof(nat_key_t)) == 0)
            { miss = &nvals[i]; break; }
    CHECK(miss == NULL, "NAT miss for unknown source IP");
}

static void test_bfd_health_update(void) {
    printf("\n--- Test: BFD health update (EMA RTT) ---\n");

    /* exponential moving average: alpha=0.25 */
    uint32_t rtt = 10000; /* initial 10ms */
    uint32_t new_samples[] = {11000, 9500, 50000, 8000, 8200};

    for (int i=0; i < 5; i++)
        rtt = (rtt * 3 + new_samples[i]) / 4;

    /* with spike to 50ms and then recovery, EMA should be between 10-20ms */
    CHECK(rtt > 8000 && rtt < 25000,
          "EMA RTT: spike absorbed, stable in 8-25ms range");
    printf("  EMA RTT after 5 samples (incl 50ms spike): %u us\n", rtt);

    /* loss_ppm calculation */
    uint32_t sent = 100, received = 97;
    uint32_t loss_ppm = (uint32_t)((uint64_t)(sent-received) * 1000000ULL / sent);
    CHECK(loss_ppm == 30000, "loss_ppm: 3/100 = 30000 ppm (3.0%)");

    uint32_t sent2 = 1000, received2 = 999;
    uint32_t loss2 = (uint32_t)((uint64_t)(sent2-received2) * 1000000ULL / sent2);
    CHECK(loss2 == 1000, "loss_ppm: 1/1000 = 1000 ppm (0.1%)");

    /* VoIP threshold check: <1000 ppm required */
    CHECK(loss2 < 1000 || loss2 == 1000, "VoIP: 0.1% loss at threshold");
    CHECK(loss_ppm >= 1000,
          "VoIP: 3.0% loss exceeds threshold → circuit avoided for VoIP");
}

int main(void) {
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║  NOS Logic Test Suite (standalone — no EAL)     ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");

    test_session_table();
    test_appid();
    test_fib();
    test_wan_selection();
    test_nat_logic();
    test_bfd_health_update();
    test_crypto_pipeline();  /* needs intel-ipsec-mb */

    printf("\n╔══════════════════════════════════════════════════╗\n");
    printf("║  Results: %d passed  %d failed                     \n",
           g_pass, g_fail);
    printf("╚══════════════════════════════════════════════════╝\n\n");
    return g_fail > 0 ? 1 : 0;
}
