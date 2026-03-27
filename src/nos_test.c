#include "nos.h"
#include "nos_crypto.h"
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_hash.h>
#include <rte_timer.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

/* forward declarations from control plane */
int  nos_control_plane_init(void);
void nos_control_plane_tick(void);

/* ============================================================
   TEST HELPERS
   ============================================================ */

static int g_tests_run = 0;
static int g_tests_passed = 0;

#define TEST_ASSERT(cond, msg) do { \
    g_tests_run++; \
    if (!(cond)) { \
        printf("  FAIL: %s  [%s:%d]\n", msg, __FILE__, __LINE__); \
    } else { \
        printf("  PASS: %s\n", msg); \
        g_tests_passed++; \
    } \
} while(0)

/* build a minimal IPv4/TCP packet into an mbuf */
static struct rte_mbuf *
make_test_pkt(uint32_t src_ip, uint32_t dst_ip,
              uint16_t sport, uint16_t dport)
{
    struct rte_mbuf *pkt = rte_pktmbuf_alloc(g_nos.pktmbuf_pool);
    if (!pkt) return NULL;

    uint32_t pkt_len = sizeof(struct rte_ether_hdr) +
                       sizeof(struct rte_ipv4_hdr) +
                       sizeof(struct rte_tcp_hdr) + 64;

    char *data = rte_pktmbuf_append(pkt, pkt_len);
    if (!data) { rte_pktmbuf_free(pkt); return NULL; }
    memset(data, 0, pkt_len);

    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)data;
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    memset(&eth->src_addr, 0xAA, 6);
    memset(&eth->dst_addr, 0xBB, 6);

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    ip->version_ihl     = 0x45;
    ip->total_length    = rte_cpu_to_be_16(pkt_len -
                              sizeof(struct rte_ether_hdr));
    ip->next_proto_id   = IPPROTO_TCP;
    ip->src_addr        = rte_cpu_to_be_32(src_ip);
    ip->dst_addr        = rte_cpu_to_be_32(dst_ip);
    ip->time_to_live    = 64;

    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
    tcp->src_port = rte_cpu_to_be_16(sport);
    tcp->dst_port = rte_cpu_to_be_16(dport);
    tcp->data_off = 0x50;
    tcp->tcp_flags = 0x02;  /* SYN */

    pkt->hash.rss = src_ip ^ dst_ip ^ sport ^ dport;  /* fake RSS hash */
    return pkt;
}

/* ============================================================
   TEST 1: SESSION TABLE
   ============================================================ */

static void test_session_table(void)
{
    printf("\n--- Test: Session Table ---\n");

    /* dummy ctx for accounting */
    nos_lcore_ctx_t ctx = {0};
    rte_atomic64_init(&ctx.pkts_dropped);
    rte_atomic64_init(&ctx.sessions_created);

    nos_session_key_t key = {
        .src_ip   = RTE_IPV4(10, 0, 0, 1),
        .dst_ip   = RTE_IPV4(8,  8, 8, 8),
        .src_port = rte_cpu_to_be_16(54321),
        .dst_port = rte_cpu_to_be_16(443),
        .proto    = IPPROTO_TCP,
    };

    /* first lookup: creates session */
    nos_session_t *s1 = nos_session_lookup_or_create(&key, &ctx);
    TEST_ASSERT(s1 != NULL, "session created on first lookup");
    TEST_ASSERT(s1->state == NOS_SESSION_NEW, "new session state = NEW");
    TEST_ASSERT(s1->pkt_count == 1, "first packet counted");

    /* second lookup: hits existing session */
    nos_session_t *s2 = nos_session_lookup_or_create(&key, &ctx);
    TEST_ASSERT(s2 == s1, "second lookup returns same session ptr");
    TEST_ASSERT(s2->pkt_count == 2, "packet counter incremented");

    /* different 5-tuple: creates different session */
    nos_session_key_t key2 = key;
    key2.src_port = rte_cpu_to_be_16(54322);
    nos_session_t *s3 = nos_session_lookup_or_create(&key2, &ctx);
    TEST_ASSERT(s3 != s1, "different 5-tuple → different session");

    uint32_t n = rte_hash_count(g_nos.session_table);
    TEST_ASSERT(n == 2, "hash table has 2 entries");

    printf("  sessions created: %lu\n",
           rte_atomic64_read(&ctx.sessions_created));
}

/* ============================================================
   TEST 2: APPID CLASSIFICATION + OFFLOAD
   ============================================================ */

static void test_appid(void)
{
    printf("\n--- Test: AppID Classification ---\n");

    nos_lcore_ctx_t ctx = {0};
    rte_atomic64_init(&ctx.pkts_dropped);
    rte_atomic64_init(&ctx.sessions_created);
    rte_atomic64_init(&ctx.sessions_offloaded);

    /* HTTPS session: dst port 443 */
    nos_session_key_t https_key = {
        .src_ip   = RTE_IPV4(192, 168, 1, 100),
        .dst_ip   = RTE_IPV4(142, 250, 80, 46),
        .src_port = rte_cpu_to_be_16(55000),
        .dst_port = rte_cpu_to_be_16(443),
        .proto    = IPPROTO_TCP,
    };
    nos_session_t *s = nos_session_lookup_or_create(&https_key, &ctx);
    struct rte_mbuf *pkt = make_test_pkt(
        RTE_IPV4(192,168,1,100), RTE_IPV4(142,250,80,46), 55000, 443);

    nos_classify_app(pkt, s);
    TEST_ASSERT(s->app_id == APP_HTTPS, "HTTPS classified on port 443");
    TEST_ASSERT(s->qos_class == 4, "HTTPS gets QoS class 4");
    rte_pktmbuf_free(pkt);

    /* VoIP session: dst port 5060 */
    nos_session_key_t voip_key = {
        .src_ip   = RTE_IPV4(192, 168, 1, 101),
        .dst_ip   = RTE_IPV4(10,  0,  0, 10),
        .src_port = rte_cpu_to_be_16(20000),
        .dst_port = rte_cpu_to_be_16(5060),
        .proto    = IPPROTO_UDP,
    };
    nos_session_t *sv = nos_session_lookup_or_create(&voip_key, &ctx);
    struct rte_mbuf *pkt2 = make_test_pkt(
        RTE_IPV4(192,168,1,101), RTE_IPV4(10,0,0,10), 20000, 5060);

    nos_classify_app(pkt2, sv);
    TEST_ASSERT(sv->app_id == APP_VOIP, "VoIP classified on port 5060");
    TEST_ASSERT(sv->qos_class == 0, "VoIP gets highest QoS class 0");
    rte_pktmbuf_free(pkt2);

    /* simulate 5 packets to trigger offload */
    struct rte_mbuf *pkts[5];
    for (int i = 0; i < 5; i++) {
        pkts[i] = make_test_pkt(
            RTE_IPV4(192,168,1,102), RTE_IPV4(8,8,8,8), 60000, 80);
    }
    nos_session_key_t http_key = {
        .src_ip   = RTE_IPV4(192, 168, 1, 102),
        .dst_ip   = RTE_IPV4(8,   8,  8,  8),
        .src_port = rte_cpu_to_be_16(60000),
        .dst_port = rte_cpu_to_be_16(80),
        .proto    = IPPROTO_TCP,
    };
    nos_session_t *sh = nos_session_lookup_or_create(&http_key, &ctx);
    for (int i = 0; i < 5; i++) {
        sh->pkt_count = i + 1;
        nos_classify_app(pkts[i], sh);
        rte_pktmbuf_free(pkts[i]);
    }
    TEST_ASSERT(sh->state == NOS_SESSION_OFFLOADED,
                "session offloaded after 5 classified packets");
    TEST_ASSERT(sh->app_id == APP_HTTP, "HTTP classified");
}

/* ============================================================
   TEST 3: AES-256-GCM ENCRYPT / DECRYPT via intel-ipsec-mb
   ============================================================ */

static void test_crypto_aes256gcm(void)
{
    printf("\n--- Test: AES-256-GCM (intel-ipsec-mb direct) ---\n");

    if (!g_crypto.mb_mgr) {
        printf("  SKIP: intel-ipsec-mb not initialized\n");
        return;
    }

    /* test vector: 256-bit key, 12-byte IV, known plaintext */
    uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    };
    uint8_t iv[12]  = { 0xca,0xfe,0xba,0xbe,0xfa,0xce,
                        0xdb,0xad,0xde,0xca,0xf8,0x88 };
    uint8_t aad[8]  = { 0xde,0xad,0xbe,0xef,0x00,0x00,0x00,0x01 };

    const char *plaintext = "Hello NOS IPSec World! This is a test payload.";
    uint32_t pt_len = strlen(plaintext);

    /* expand key for SA slot 0 */
    IMB_AES256_GCM_PRE(g_crypto.mb_mgr, key, &g_crypto.sa_ctx[0].expanded);
    g_crypto.sa_ctx[0].initialized = true;

    uint8_t ciphertext[256] = {0};
    uint8_t tag[16]         = {0};
    uint8_t decrypted[256]  = {0};
    uint8_t verify_tag[16]  = {0};

    /* encrypt */
    IMB_AES256_GCM_ENC(
        g_crypto.mb_mgr,
        &g_crypto.sa_ctx[0].expanded,
        &g_crypto.sa_ctx[0].gcm_ctx,
        ciphertext,
        (uint8_t *)plaintext, pt_len,
        iv, aad, sizeof(aad),
        tag, 16);

    TEST_ASSERT(memcmp(ciphertext, plaintext, pt_len) != 0,
                "ciphertext differs from plaintext");
    printf("  encrypt OK:  first 8 cipher bytes: "
           "%02x %02x %02x %02x %02x %02x %02x %02x\n",
           ciphertext[0], ciphertext[1], ciphertext[2], ciphertext[3],
           ciphertext[4], ciphertext[5], ciphertext[6], ciphertext[7]);
    printf("  GCM auth tag: "
           "%02x%02x%02x%02x%02x%02x%02x%02x"
           "%02x%02x%02x%02x%02x%02x%02x%02x\n",
           tag[0],tag[1],tag[2],tag[3],tag[4],tag[5],tag[6],tag[7],
           tag[8],tag[9],tag[10],tag[11],tag[12],tag[13],tag[14],tag[15]);

    /* decrypt */
    IMB_AES256_GCM_DEC(
        g_crypto.mb_mgr,
        &g_crypto.sa_ctx[0].expanded,
        &g_crypto.sa_ctx[0].gcm_ctx,
        decrypted,
        ciphertext, pt_len,
        iv, aad, sizeof(aad),
        verify_tag, 16);

    TEST_ASSERT(memcmp(decrypted, plaintext, pt_len) == 0,
                "decrypted matches original plaintext");
    TEST_ASSERT(memcmp(tag, verify_tag, 16) == 0,
                "GCM authentication tag verified");

    /* tamper test: flip one ciphertext bit, verify tag fails */
    ciphertext[4] ^= 0xFF;
    uint8_t bad_tag[16] = {0};
    IMB_AES256_GCM_DEC(
        g_crypto.mb_mgr,
        &g_crypto.sa_ctx[0].expanded,
        &g_crypto.sa_ctx[0].gcm_ctx,
        decrypted,
        ciphertext, pt_len,
        iv, aad, sizeof(aad),
        bad_tag, 16);

    TEST_ASSERT(memcmp(bad_tag, tag, 16) != 0,
                "tampered ciphertext produces different auth tag");

    /* report ISA path used */
    const char *arch_names[] = {"NONE","NOAESNI","SSE","AVX","AVX2","AVX512"};
    printf("  ISA path: %s  (AES instructions: %s)\n",
           arch_names[g_crypto.mb_arch],
           g_crypto.mb_arch >= IMB_ARCH_SSE ? "AESENC/AESDEC" : "software");
}

/* ============================================================
   TEST 4: LPM FIB ROUTING
   ============================================================ */

static void test_fib(void)
{
    printf("\n--- Test: LPM FIB ---\n");

    /* routes seeded in nos_fib_init():
       0.0.0.0/0  → 0  (default / WAN)
       10.0.0.0/8 → 1  (LAN) */

    uint32_t nh;
    int ret;

    ret = rte_lpm_lookup(g_nos.lpm_v4, RTE_IPV4(8, 8, 8, 8), &nh);
    TEST_ASSERT(ret == 0 && nh == 0,
                "8.8.8.8 → default route → port 0");

    ret = rte_lpm_lookup(g_nos.lpm_v4, RTE_IPV4(10, 1, 2, 3), &nh);
    TEST_ASSERT(ret == 0 && nh == 1,
                "10.1.2.3 → 10/8 route → port 1");

    /* add a more specific route and verify LPM prefers it */
    rte_lpm_add(g_nos.lpm_v4, RTE_IPV4(8, 8, 8, 0), 24, 2);
    ret = rte_lpm_lookup(g_nos.lpm_v4, RTE_IPV4(8, 8, 8, 8), &nh);
    TEST_ASSERT(ret == 0 && nh == 2,
                "8.8.8.8 → /24 more specific beats /0 default");

    ret = rte_lpm_lookup(g_nos.lpm_v4, RTE_IPV4(8, 8, 4, 4), &nh);
    TEST_ASSERT(ret == 0 && nh == 0,
                "8.8.4.4 → still uses default (not in /24)");
}

/* ============================================================
   TEST 5: WAN PATH SELECTION
   ============================================================ */

static void test_wan_path_selection(void)
{
    printf("\n--- Test: WAN Path Selection ---\n");

    /* configure two circuits with different RTTs */
    g_nos.n_wan = 2;
    g_nos.wan[0].active   = true;
    g_nos.wan[0].rtt_us   = 5000;    /* 5ms */
    g_nos.wan[0].loss_ppm = 0;

    g_nos.wan[1].active   = true;
    g_nos.wan[1].rtt_us   = 50000;   /* 50ms */
    g_nos.wan[1].loss_ppm = 0;

    nos_session_t sess = {0};

    /* bulk traffic → lower score (RTT) wins */
    sess.app_id = APP_BULK;
    int path = nos_select_wan_path(&sess);
    TEST_ASSERT(path == 0, "bulk: lower RTT circuit selected (port 0)");

    /* invert RTTs */
    g_nos.wan[0].rtt_us = 80000;
    g_nos.wan[1].rtt_us = 3000;
    path = nos_select_wan_path(&sess);
    TEST_ASSERT(path == 1, "bulk: updated RTT now selects port 1");

    /* VoIP: strict loss requirement */
    sess.app_id = APP_VOIP;
    g_nos.wan[0].rtt_us   = 10000;
    g_nos.wan[0].loss_ppm = 5000;    /* 0.5% loss — above 0.1% threshold */
    g_nos.wan[1].rtt_us   = 20000;
    g_nos.wan[1].loss_ppm = 100;     /* 0.01% loss — acceptable */
    path = nos_select_wan_path(&sess);
    TEST_ASSERT(path == 1, "VoIP: higher RTT but lower loss circuit preferred");

    /* mark circuit 0 down → circuit 1 only option */
    g_nos.wan[0].active = false;
    sess.app_id = APP_HTTPS;
    path = nos_select_wan_path(&sess);
    TEST_ASSERT(path == 1, "HTTPS: only active circuit selected when 0 is down");

    g_nos.wan[0].active = true;   /* restore */
}

/* ============================================================
   TEST 6: FULL PACKET PIPELINE (end-to-end burst)
   ============================================================ */

static void test_packet_pipeline(void)
{
    printf("\n--- Test: Full Packet Pipeline ---\n");

    nos_lcore_ctx_t ctx = {0};
    ctx.lcore_id = rte_get_main_lcore();
    rte_atomic64_init(&ctx.pkts_rx);
    rte_atomic64_init(&ctx.pkts_tx);
    rte_atomic64_init(&ctx.pkts_dropped);
    rte_atomic64_init(&ctx.sessions_created);
    rte_atomic64_init(&ctx.sessions_offloaded);

    /* set up a fake TX ring for the pipeline to enqueue into */
    struct rte_ring *fake_tx = rte_ring_create(
        "test_tx", 4096, rte_socket_id(),
        RING_F_SP_ENQ | RING_F_SC_DEQ);
    struct rte_ring *saved = g_nos.worker_to_poller;
    g_nos.worker_to_poller = fake_tx;

    /* build a burst of 8 test packets */
    struct rte_mbuf *burst[8];
    uint32_t src_base = RTE_IPV4(10, 1, 1, 0);
    for (int i = 0; i < 8; i++) {
        burst[i] = make_test_pkt(
            src_base + i,
            RTE_IPV4(8, 8, 8, 8),
            50000 + i, 443);   /* HTTPS */
    }

    nos_process_burst(burst, 8, &ctx);

    uint64_t tx  = rte_atomic64_read(&ctx.pkts_tx);
    uint64_t drop = rte_atomic64_read(&ctx.pkts_dropped);

    TEST_ASSERT(tx + drop == 8,
                "all 8 packets accounted for (tx + drop = 8)");
    TEST_ASSERT(tx >= 6, "most packets forwarded to TX ring");

    /* verify sessions created */
    uint64_t sess = rte_atomic64_read(&ctx.sessions_created);
    TEST_ASSERT(sess == 8, "8 new sessions created (one per unique src IP)");

    /* drain fake TX ring */
    struct rte_mbuf *out[64];
    uint32_t n = rte_ring_dequeue_burst(fake_tx, (void **)out, 64, NULL);
    for (uint32_t i = 0; i < n; i++) rte_pktmbuf_free(out[i]);

    g_nos.worker_to_poller = saved;
    rte_ring_free(fake_tx);

    printf("  burst result: %lu forwarded, %lu dropped\n", tx, drop);
}

/* ============================================================
   MAIN TEST RUNNER
   ============================================================ */

int main(int argc, char **argv)
{
    printf("╔═══════════════════════════════════════════╗\n");
    printf("║  NOS-like DPDK — Unit Test Suite          ║\n");
    printf("╚═══════════════════════════════════════════╝\n");

    /* EAL: --no-huge runs without hugepages (portable test env) */
    int ret = nos_init(argc, argv);
    if (ret != 0) {
        printf("NOS init failed\n");
        return 1;
    }

    /* init crypto engine */
    nos_crypto_init();
    nos_crypto_show_capabilities();

    /* init control plane (routes, NAT, BFD) */
    nos_control_plane_init();

    /* run tests */
    test_session_table();
    test_appid();
    test_crypto_aes256gcm();
    test_fib();
    test_wan_path_selection();
    test_packet_pipeline();

    /* tick BFD once to show the timer callback works */
    printf("\n--- BFD probe tick ---\n");
    nos_control_plane_tick();

    /* summary */
    printf("\n╔═══════════════════════════════════════════╗\n");
    printf("║  Results: %d/%d tests passed               \n",
           g_tests_passed, g_tests_run);
    printf("╚═══════════════════════════════════════════╝\n\n");

    nos_stats_dump();

    rte_eal_cleanup();
    return (g_tests_passed == g_tests_run) ? 0 : 1;
}
