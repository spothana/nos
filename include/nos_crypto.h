#pragma once
#include <intel-ipsec-mb.h>
#include <rte_cryptodev.h>
#include <rte_crypto.h>
#include <stdint.h>
#include <stdbool.h>

/* ============================================================
   CRYPTO ENGINE — supports two execution paths:

   PATH A: intel-ipsec-mb direct (software, synchronous)
     - alloc_mb_mgr() + init_mb_mgr_auto() at startup
     - Selects AVX512/AVX2/SSE based on CPUID at runtime
     - AES-256-GCM via IMB_AES256_GCM_ENC/DEC macros
     - Best for: moderate throughput, simple deployment
     - ISA used: AESENC, PCLMULQDQ, VAES (if AVX512+VAES)

   PATH B: DPDK rte_cryptodev (PMD abstraction)
     - crypto_ipsec_mb PMD (wraps intel-ipsec-mb via DPDK)
     - OR crypto_openssl PMD (fallback)
     - OR crypto_qat PMD (hardware offload, async)
     - Accessed via rte_cryptodev_enqueue/dequeue_burst()
     - Best for: QAT hardware, multi-queue, production scale

   NOS uses PATH B in production (crypto PMD via DPDK).
   PATH A is exposed here to show the raw ISA interaction.
   ============================================================ */

#define NOS_AES_GCM_IV_LEN   12   /* bytes — standard GCM IV */
#define NOS_AES_GCM_TAG_LEN  16   /* bytes — full 128-bit auth tag */
#define NOS_AES_256_KEY_LEN  32   /* bytes */
#define NOS_CRYPTO_OP_POOL_SIZE  (1 << 14)  /* 16K ops */

/* per-SA expanded key material (computed once at SA creation) */
typedef struct {
    struct gcm_key_data  expanded;       /* intel-ipsec-mb expanded key */
    struct gcm_context_data gcm_ctx;     /* reused per encrypt call */
    uint8_t  raw_key[NOS_AES_256_KEY_LEN];
    bool     initialized;
} nos_crypto_sa_ctx_t;

/* global crypto engine state */
typedef struct {
    /* intel-ipsec-mb manager — PATH A */
    IMB_MGR             *mb_mgr;
    IMB_ARCH             mb_arch;       /* detected: SSE/AVX2/AVX512 */

    /* DPDK cryptodev — PATH B */
    uint8_t              cdev_id;
    bool                 cdev_ready;
    struct rte_mempool  *crypto_op_pool;
    void                *session_pool;  /* rte_mempool for sym sessions */

    /* per-SA expanded key cache */
    nos_crypto_sa_ctx_t  sa_ctx[NOS_MAX_TUNNELS];

    /* stats */
    uint64_t             pkts_encrypted;
    uint64_t             pkts_decrypted;
    uint64_t             bytes_encrypted;
    uint64_t             auth_failures;
} nos_crypto_engine_t;

extern nos_crypto_engine_t g_crypto;

/* function declarations */
int  nos_crypto_init(void);
void nos_crypto_show_capabilities(void);

/* PATH A: direct intel-ipsec-mb */
int  nos_crypto_aes256gcm_encrypt(uint8_t sa_idx,
                                   uint8_t *plaintext,  uint32_t pt_len,
                                   uint8_t *iv,
                                   uint8_t *aad,        uint32_t aad_len,
                                   uint8_t *ciphertext,
                                   uint8_t *tag);

int  nos_crypto_aes256gcm_decrypt(uint8_t sa_idx,
                                   uint8_t *ciphertext, uint32_t ct_len,
                                   uint8_t *iv,
                                   uint8_t *aad,        uint32_t aad_len,
                                   uint8_t *plaintext,
                                   uint8_t *tag);

/* PATH B: DPDK cryptodev */
int  nos_cryptodev_init(void);
int  nos_cryptodev_session_create(uint8_t sa_idx, uint8_t *key);
int  nos_cryptodev_enqueue_encrypt(struct rte_mbuf *pkt, uint8_t sa_idx);
int  nos_cryptodev_poll_completions(struct rte_mbuf **out, uint16_t max);
