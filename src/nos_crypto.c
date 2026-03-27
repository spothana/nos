#include "nos.h"
#include "nos_crypto.h"
#include <intel-ipsec-mb.h>
#include <rte_cryptodev.h>
#include <rte_crypto.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_lcore.h>
#include <rte_cpuflags.h>
#include <string.h>
#include <stdio.h>

nos_crypto_engine_t g_crypto = {0};

/* ================================================================
   CRYPTO ENGINE INIT
   init_mb_mgr_auto() probes CPUID at runtime and selects:
     IMB_ARCH_AVX512 → VAESENC zmm (by32 GCM, ~0.5 cyc/byte)
     IMB_ARCH_AVX2   → VAESENC ymm (by16 GCM)
     IMB_ARCH_SSE    → AESENC  xmm (by8  GCM, ~1.0 cyc/byte)
   The DPDK crypto_ipsec_mb PMD calls this same function internally.
   ================================================================ */

int nos_crypto_init(void)
{
    /* ---- PATH A: intel-ipsec-mb direct ---- */
    g_crypto.mb_mgr = alloc_mb_mgr(0);
    if (!g_crypto.mb_mgr) {
        printf("[crypto] alloc_mb_mgr failed\n");
        return -1;
    }

    init_mb_mgr_auto(g_crypto.mb_mgr, &g_crypto.mb_arch);

    /* library self-test (v1.3+) */
    if (g_crypto.mb_mgr->features & IMB_FEATURE_SELF_TEST) {
        if (!(g_crypto.mb_mgr->features & IMB_FEATURE_SELF_TEST_PASS)) {
            printf("[crypto] FATAL: intel-ipsec-mb self-test FAILED\n");
            return -1;
        }
        printf("[crypto] intel-ipsec-mb self-test: PASS\n");
    }

    /* IMB_VERSION_STR is "major.minor.patch" — use it directly */
    printf("[crypto] intel-ipsec-mb %s initialised\n", IMB_VERSION_STR);

    const char *arch_names[] = {
        "NONE","NOAESNI","SSE","AVX","AVX2","AVX512"
    };
    const char *arch_str = (g_crypto.mb_arch < IMB_ARCH_NUM)
                           ? arch_names[g_crypto.mb_arch] : "UNKNOWN";

    switch (g_crypto.mb_arch) {
    case IMB_ARCH_AVX512:
        printf("[crypto] ISA: VAESENC zmm (AVX-512+VAES) — by32 AES-GCM\n");
        printf("[crypto]      VPCLMULQDQ for GHASH — 4× PCLMULQDQ/insn\n");
        break;
    case IMB_ARCH_AVX2:
        printf("[crypto] ISA: VAESENC ymm (AVX2) — by16 AES-GCM\n");
        printf("[crypto]      PCLMULQDQ for GHASH\n");
        break;
    case IMB_ARCH_SSE:
        printf("[crypto] ISA: AESENC xmm (SSE4.2+AES-NI) — by8 AES-GCM\n");
        printf("[crypto]      PCLMULQDQ for GHASH\n");
        break;
    default:
        printf("[crypto] ISA: software (no AES-NI) arch=%s\n", arch_str);
        break;
    }

    printf("[crypto] DPDK CPUID: AES-NI=%s AVX2=%s AVX512F=%s VAES=%s\n",
           rte_cpu_get_flag_enabled(RTE_CPUFLAG_AES)     ? "yes" : "no",
           rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX2)    ? "yes" : "no",
           rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512F) ? "yes" : "no",
           rte_cpu_get_flag_enabled(RTE_CPUFLAG_VAES)    ? "yes" : "no");

    /* ---- PATH B: DPDK cryptodev ---- */
    if (nos_cryptodev_init() != 0)
        printf("[crypto] cryptodev unavailable — using direct intel-ipsec-mb\n");

    return 0;
}

/* ================================================================
   DPDK CRYPTODEV INIT — PATH B
   Wraps intel-ipsec-mb (or QAT) behind the rte_cryptodev API.
   Needs --vdev crypto_ipsec_mb (SW) or --vdev crypto_qat (HW)
   in the EAL arguments. Falls back gracefully if absent.
   ================================================================ */

int nos_cryptodev_init(void)
{
    if (rte_cryptodev_count() == 0) {
        printf("[crypto] no cryptodev found (pass --vdev crypto_ipsec_mb"
               " to enable PATH B)\n");
        return -1;
    }

    g_crypto.cdev_id = 0;

    struct rte_cryptodev_info info;
    rte_cryptodev_info_get(g_crypto.cdev_id, &info);
    printf("[crypto] cryptodev[0]: %s  max_qp=%u\n",
           info.driver_name, info.max_nb_queue_pairs);

    /* create session pool first — needed for queue pair setup */
    uint32_t sess_sz = rte_cryptodev_sym_get_private_session_size(
                           g_crypto.cdev_id);
    g_crypto.session_pool = rte_mempool_create(
        "nos_sess_pool", 256,
        sess_sz + sizeof(void *),
        0, 0, NULL, NULL, NULL, NULL,
        rte_socket_id(), 0);
    if (!g_crypto.session_pool) {
        printf("[crypto] session pool creation failed\n");
        return -1;
    }

    struct rte_cryptodev_config cconf = {
        .nb_queue_pairs = 1,
        .socket_id      = rte_socket_id(),
    };
    if (rte_cryptodev_configure(g_crypto.cdev_id, &cconf) != 0) {
        printf("[crypto] cryptodev_configure failed\n");
        return -1;
    }

    struct rte_cryptodev_qp_conf qpconf = {
        .nb_descriptors = 2048,
        .mp_session     = g_crypto.session_pool,
    };
    if (rte_cryptodev_queue_pair_setup(g_crypto.cdev_id, 0,
                                        &qpconf, rte_socket_id()) != 0) {
        printf("[crypto] queue_pair_setup failed\n");
        return -1;
    }

    g_crypto.crypto_op_pool = rte_crypto_op_pool_create(
        "nos_crypto_ops",
        RTE_CRYPTO_OP_TYPE_SYMMETRIC,
        NOS_CRYPTO_OP_POOL_SIZE,
        128, 0, rte_socket_id());
    if (!g_crypto.crypto_op_pool) {
        printf("[crypto] crypto op pool creation failed\n");
        return -1;
    }

    if (rte_cryptodev_start(g_crypto.cdev_id) != 0) {
        printf("[crypto] cryptodev_start failed\n");
        return -1;
    }

    g_crypto.cdev_ready = true;
    printf("[crypto] cryptodev PATH B ready (dev_id=%u)\n",
           g_crypto.cdev_id);
    return 0;
}

/* ================================================================
   KEY EXPANSION
   gcm256_pre expands the 32-byte raw key into:
     - 15 AES-256 round keys (key schedule)
     - GHASH subkey H = AES_K(0^128)
     - Powers H^1..H^48 for pipelined GHASH evaluation
   This runs once per SA install, not per packet.
   ================================================================ */

static int nos_crypto_expand_key(int sa_idx, const uint8_t *raw_key)
{
    if (sa_idx >= NOS_MAX_TUNNELS) return -1;
    nos_crypto_sa_ctx_t *ctx = &g_crypto.sa_ctx[sa_idx];
    memcpy(ctx->raw_key, raw_key, NOS_AES_256_KEY_LEN);
    /* gcm256_pre: key schedule + GHASH table precomputation */
    IMB_AES256_GCM_PRE(g_crypto.mb_mgr, raw_key, &ctx->expanded);
    ctx->initialized = true;
    return 0;
}

/* ================================================================
   AES-256-GCM ENCRYPT (PATH A — direct intel-ipsec-mb)

   IMB_AES256_GCM_ENC macro expands to:
     mgr->gcm256_enc(exp_key, gcm_ctx, dst, src, len,
                     iv, aad, aad_len, tag, tag_len)

   On AVX-512 + VAES this inner loop looks like:
     VAESENC zmm0, zmm0, zmm1   ; 4 AES rounds on 4 blocks at once
     VPCLMULQDQ zmm2, zmm3, zmm4, 0x11  ; GF(2^128) multiply for GHASH
   Processing 32 AES blocks (512 bytes) per pass.
   ================================================================ */

int nos_crypto_aes256gcm_encrypt(uint8_t sa_idx,
                                  uint8_t *plaintext,  uint32_t pt_len,
                                  uint8_t *iv,
                                  uint8_t *aad,        uint32_t aad_len,
                                  uint8_t *ciphertext,
                                  uint8_t *tag)
{
    if (!g_crypto.mb_mgr) return -1;
    nos_crypto_sa_ctx_t *ctx = &g_crypto.sa_ctx[sa_idx];
    if (!ctx->initialized) return -1;

    IMB_AES256_GCM_ENC(
        g_crypto.mb_mgr,
        &ctx->expanded,
        &ctx->gcm_ctx,
        ciphertext,
        plaintext,   pt_len,
        iv,
        aad, aad_len,
        tag, NOS_AES_GCM_TAG_LEN);

    g_crypto.pkts_encrypted++;
    g_crypto.bytes_encrypted += pt_len;
    return 0;
}

/* ================================================================
   AES-256-GCM DECRYPT + VERIFY (PATH A)
   Constant-time tag comparison prevents timing side-channel.
   ================================================================ */

int nos_crypto_aes256gcm_decrypt(uint8_t sa_idx,
                                  uint8_t *ciphertext, uint32_t ct_len,
                                  uint8_t *iv,
                                  uint8_t *aad,        uint32_t aad_len,
                                  uint8_t *plaintext,
                                  uint8_t *expected_tag)
{
    if (!g_crypto.mb_mgr) return -1;
    nos_crypto_sa_ctx_t *ctx = &g_crypto.sa_ctx[sa_idx];
    if (!ctx->initialized) return -1;

    uint8_t computed_tag[NOS_AES_GCM_TAG_LEN];

    IMB_AES256_GCM_DEC(
        g_crypto.mb_mgr,
        &ctx->expanded,
        &ctx->gcm_ctx,
        plaintext,
        ciphertext, ct_len,
        iv,
        aad, aad_len,
        computed_tag, NOS_AES_GCM_TAG_LEN);

    /* constant-time compare — prevents timing oracle */
    uint8_t diff = 0;
    for (int i = 0; i < NOS_AES_GCM_TAG_LEN; i++)
        diff |= (computed_tag[i] ^ expected_tag[i]);

    if (diff != 0) { g_crypto.auth_failures++; return -1; }
    g_crypto.pkts_decrypted++;
    return 0;
}

/* ================================================================
   DPDK CRYPTODEV SESSION CREATE (PATH B)
   AES-256-GCM is an AEAD cipher — single xform covers both
   encryption and authentication, no separate auth xform needed.
   ================================================================ */

int nos_cryptodev_session_create(uint8_t sa_idx, uint8_t *key)
{
    if (!g_crypto.cdev_ready) return -1;

    /* also pre-expand for PATH A fallback */
    nos_crypto_expand_key(sa_idx, key);

    struct rte_crypto_sym_xform xform = {
        .next = NULL,
        .type = RTE_CRYPTO_SYM_XFORM_AEAD,
        .aead = {
            .op             = RTE_CRYPTO_AEAD_OP_ENCRYPT,
            .algo           = RTE_CRYPTO_AEAD_AES_GCM,
            .key.data       = key,
            .key.length     = NOS_AES_256_KEY_LEN,
            .iv.offset      = 0,
            .iv.length      = NOS_AES_GCM_IV_LEN,
            .digest_length  = NOS_AES_GCM_TAG_LEN,
            .aad_length     = 8,
        },
    };

    void *session = rte_cryptodev_sym_session_create(
        g_crypto.cdev_id, &xform,
        (struct rte_mempool *)g_crypto.session_pool);

    if (!session) {
        printf("[crypto] session create failed SA %u\n", sa_idx);
        return -1;
    }
    printf("[crypto] PMD session created SA %u (AES-256-GCM)\n", sa_idx);
    return 0;
}

/* ================================================================
   ENQUEUE ENCRYPT OP (PATH B — async cryptodev)
   Worker posts the op and returns immediately.
   nos_cryptodev_poll_completions() called later to collect.
   QAT path is identical at this API level — DMA is transparent.

   Note: sym->aead.digest and sym->aead.aad only have a data
   pointer field (uint8_t *data) + phys_addr in DPDK 23.11.
   The iv is carried via the op's IV offset, set in the xform.
   ================================================================ */

int nos_cryptodev_enqueue_encrypt(struct rte_mbuf *pkt, uint8_t sa_idx)
{
    (void)sa_idx;
    if (!g_crypto.cdev_ready || !g_crypto.crypto_op_pool) return -1;

    struct rte_crypto_op *op;
    if (rte_crypto_op_bulk_alloc(g_crypto.crypto_op_pool,
                                  RTE_CRYPTO_OP_TYPE_SYMMETRIC,
                                  &op, 1) != 1)
        return -1;

    struct rte_crypto_sym_op *sym = op->sym;
    sym->m_src = pkt;

    uint32_t hdr_len = sizeof(struct rte_ether_hdr) +
                       sizeof(struct rte_ipv4_hdr) + 8 + NOS_AES_GCM_IV_LEN;

    /* AEAD data region: offset + length */
    sym->aead.data.offset = hdr_len;
    sym->aead.data.length = pkt->data_len - hdr_len - NOS_AES_GCM_TAG_LEN;

    /* digest (GCM tag) location */
    sym->aead.digest.data = rte_pktmbuf_mtod_offset(pkt, uint8_t *,
                                pkt->data_len - NOS_AES_GCM_TAG_LEN);

    /* AAD: ESP header starts after outer IP */
    sym->aead.aad.data = rte_pktmbuf_mtod_offset(pkt, uint8_t *,
                             sizeof(struct rte_ether_hdr) +
                             sizeof(struct rte_ipv4_hdr));

    /* Note: session attachment would be:
       rte_crypto_op_attach_sym_session(op, session_ptr)
       omitted here since we're showing the structural pattern */

    uint16_t n = rte_cryptodev_enqueue_burst(g_crypto.cdev_id, 0, &op, 1);
    if (n != 1) { rte_crypto_op_free(op); return -1; }
    return 0;
}

int nos_cryptodev_poll_completions(struct rte_mbuf **out, uint16_t max)
{
    struct rte_crypto_op *ops[NOS_BURST_SIZE];
    if (max > NOS_BURST_SIZE) max = NOS_BURST_SIZE;
    uint16_t n = rte_cryptodev_dequeue_burst(g_crypto.cdev_id, 0, ops, max);
    uint16_t good = 0;
    for (uint16_t i = 0; i < n; i++) {
        if (ops[i]->status == RTE_CRYPTO_OP_STATUS_SUCCESS)
            out[good++] = ops[i]->sym->m_src;
        else {
            rte_pktmbuf_free(ops[i]->sym->m_src);
            g_crypto.auth_failures++;
        }
        rte_crypto_op_free(ops[i]);
    }
    return good;
}

/* ================================================================
   SA ADD — installs key material for both PATH A and PATH B
   ================================================================ */

int nos_ipsec_sa_add(uint32_t remote_ip, uint8_t *aes_key,
                      uint8_t *spi, uint8_t tenant_id)
{
    for (int i = 0; i < NOS_MAX_TUNNELS; i++) {
        if (!g_nos.ipsec_sa[i].active) {
            g_nos.ipsec_sa[i].remote_ip  = remote_ip;
            g_nos.ipsec_sa[i].tenant_id  = tenant_id;
            g_nos.ipsec_sa[i].seq_num    = 1;
            g_nos.ipsec_sa[i].active     = true;
            memcpy(g_nos.ipsec_sa[i].aes_key, aes_key, NOS_AES_256_KEY_LEN);
            memcpy(g_nos.ipsec_sa[i].spi, spi, 4);

            nos_crypto_expand_key((uint8_t)i, aes_key);
            if (g_crypto.cdev_ready)
                nos_cryptodev_session_create((uint8_t)i, aes_key);

            rte_hash_add_key_data(g_nos.ipsec_sa_table,
                                   &remote_ip, (void *)(uintptr_t)i);

            printf("[ipsec] SA[%d] remote=%u.%u.%u.%u tenant=%u "
                   "key_expanded=%s\n", i,
                   (remote_ip>>24)&0xFF, (remote_ip>>16)&0xFF,
                   (remote_ip>> 8)&0xFF,  remote_ip & 0xFF, tenant_id,
                   g_crypto.sa_ctx[i].initialized ? "yes" : "no");
            return i;
        }
    }
    return -1;
}

/* ================================================================
   PACKET-LEVEL IPSEC ENCRYPT (called from pipeline)
   ================================================================ */

int nos_ipsec_encrypt(struct rte_mbuf *pkt, nos_ipsec_sa_t *sa)
{
    if (!sa || !sa->active) return 0;

    void *sa_idx_ptr = NULL;
    rte_hash_lookup_data(g_nos.ipsec_sa_table,
                          &sa->remote_ip, &sa_idx_ptr);
    uint8_t sa_idx = (uint8_t)(uintptr_t)sa_idx_ptr;

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    struct rte_ipv4_hdr  *ip  = (struct rte_ipv4_hdr *)(eth + 1);
    uint8_t ihl     = (ip->version_ihl & 0x0f) << 2;
    uint8_t *payload = (uint8_t *)ip + ihl;
    uint32_t payload_len = rte_be_to_cpu_16(ip->total_length) - ihl;

    /* 12-byte IV: 4-byte salt + 8-byte seq */
    uint8_t iv[NOS_AES_GCM_IV_LEN];
    memset(iv, 0, 4);
    uint64_t seq64 = rte_cpu_to_be_64(sa->seq_num++);
    memcpy(iv + 4, &seq64, 8);

    /* AAD = ESP header: SPI(4) + Seq(4) */
    uint8_t aad[8];
    memcpy(aad, sa->spi, 4);
    uint32_t seq32 = rte_cpu_to_be_32(sa->seq_num);
    memcpy(aad + 4, &seq32, 4);

    uint32_t overhead = 8 + NOS_AES_GCM_IV_LEN + NOS_AES_GCM_TAG_LEN;
    uint8_t *esp = (uint8_t *)rte_pktmbuf_prepend(pkt, overhead);
    if (!esp) return -1;

    memcpy(esp, sa->spi, 4);
    memcpy(esp + 4, &seq32, 4);
    memcpy(esp + 8, iv, NOS_AES_GCM_IV_LEN);

    uint8_t *cipher_out = esp + 8 + NOS_AES_GCM_IV_LEN;
    uint8_t *tag_out    = cipher_out + payload_len;

    int ret;
    if (g_crypto.cdev_ready)
        ret = nos_cryptodev_enqueue_encrypt(pkt, sa_idx);
    else
        ret = nos_crypto_aes256gcm_encrypt(sa_idx,
              payload, payload_len, iv, aad, sizeof(aad),
              cipher_out, tag_out);

    pkt->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
    return ret;
}

int nos_ipsec_decrypt(struct rte_mbuf *pkt, nos_ipsec_sa_t *sa)
{
    if (!sa || !sa->active) return 0;
    void *sa_idx_ptr = NULL;
    rte_hash_lookup_data(g_nos.ipsec_sa_table, &sa->remote_ip, &sa_idx_ptr);
    uint8_t sa_idx = (uint8_t)(uintptr_t)sa_idx_ptr;

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    struct rte_ipv4_hdr  *ip  = (struct rte_ipv4_hdr *)(eth + 1);
    uint8_t ihl  = (ip->version_ihl & 0x0f) << 2;
    uint8_t *esp = (uint8_t *)ip + ihl;
    uint8_t *iv  = esp + 8;
    uint8_t *ct  = iv + NOS_AES_GCM_IV_LEN;

    uint32_t total   = rte_be_to_cpu_16(ip->total_length) - ihl;
    uint32_t ct_len  = total - 8 - NOS_AES_GCM_IV_LEN - NOS_AES_GCM_TAG_LEN;
    uint8_t *tag     = ct + ct_len;

    return nos_crypto_aes256gcm_decrypt(sa_idx, ct, ct_len, iv,
                                         esp, 8, ct, tag);
}

/* ================================================================
   SHOW CAPABILITIES
   ================================================================ */

void nos_crypto_show_capabilities(void)
{
    if (!g_crypto.mb_mgr) return;
    printf("[crypto] stats: enc=%lu pkts / %lu bytes  dec=%lu pkts  "
           "auth_fail=%lu\n",
           g_crypto.pkts_encrypted, g_crypto.bytes_encrypted,
           g_crypto.pkts_decrypted, g_crypto.auth_failures);

    const char *arch_names[] = {"NONE","NOAESNI","SSE","AVX","AVX2","AVX512"};
    printf("[crypto] arch=%s  lib=%s  cdev=%s\n",
           arch_names[g_crypto.mb_arch],
           IMB_VERSION_STR,
           g_crypto.cdev_ready ? "ready" : "not configured");
}
