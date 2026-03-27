#include <intel-ipsec-mb.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define TAG_LEN  16
#define KEY_LEN  32
#define IV_LEN   12

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  PASS: %s\n", msg); g_pass++; } \
    else       { printf("  FAIL: %s\n", msg); g_fail++; } \
} while(0)

int main(void) {
    printf("╔══════════════════════════════════════════╗\n");
    printf("║  intel-ipsec-mb standalone crypto tests  ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

    /* init manager */
    IMB_MGR *mgr = alloc_mb_mgr(0);
    if (!mgr) { printf("alloc_mb_mgr failed\n"); return 1; }

    IMB_ARCH arch;
    init_mb_mgr_auto(mgr, &arch);

    const char *arch_names[] = {"NONE","NOAESNI","SSE","AVX","AVX2","AVX512"};
    printf("[crypto] library: %s\n", IMB_VERSION_STR);
    printf("[crypto] arch:    %s\n", arch < IMB_ARCH_NUM ? arch_names[arch] : "?");

    /* self-test */
    if (mgr->features & IMB_FEATURE_SELF_TEST) {
        CHECK(mgr->features & IMB_FEATURE_SELF_TEST_PASS,
              "intel-ipsec-mb self-test passed");
    }

    /* --- Test 1: AES-256-GCM key expansion --- */
    printf("\n--- Test 1: AES-256-GCM key expansion ---\n");
    uint8_t key[KEY_LEN];
    for (int i = 0; i < KEY_LEN; i++) key[i] = i;

    struct gcm_key_data exp_key;
    IMB_AES256_GCM_PRE(mgr, key, &exp_key);
    /* spot-check: expanded_keys[0] should not be all zeros */
    int nonzero = 0;
    for (int i = 0; i < 16; i++) nonzero |= exp_key.expanded_keys[i];
    CHECK(nonzero != 0, "key schedule expansion produced non-zero output");

    /* --- Test 2: encrypt / decrypt round-trip --- */
    printf("\n--- Test 2: AES-256-GCM encrypt/decrypt round-trip ---\n");
    uint8_t iv[IV_LEN]  = {0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88};
    uint8_t aad[8]      = {0xde,0xad,0xbe,0xef,0x00,0x00,0x00,0x01};
    const char *plain   = "Hello NOS AES-256-GCM! This is a 48-byte test vec.";
    uint32_t    plen    = strlen(plain);
    uint8_t     cipher[64]  = {0};
    uint8_t     tag_enc[16] = {0};
    uint8_t     recovered[64] = {0};
    uint8_t     tag_dec[16]   = {0};
    struct gcm_context_data ctx;

    IMB_AES256_GCM_ENC(mgr, &exp_key, &ctx,
        cipher, (uint8_t*)plain, plen,
        iv, aad, sizeof(aad), tag_enc, TAG_LEN);

    CHECK(memcmp(cipher, plain, plen) != 0,
          "ciphertext differs from plaintext");
    printf("  tag: %02x%02x%02x%02x%02x%02x%02x%02x"
                  "%02x%02x%02x%02x%02x%02x%02x%02x\n",
           tag_enc[0],tag_enc[1],tag_enc[2],tag_enc[3],
           tag_enc[4],tag_enc[5],tag_enc[6],tag_enc[7],
           tag_enc[8],tag_enc[9],tag_enc[10],tag_enc[11],
           tag_enc[12],tag_enc[13],tag_enc[14],tag_enc[15]);

    IMB_AES256_GCM_DEC(mgr, &exp_key, &ctx,
        recovered, cipher, plen,
        iv, aad, sizeof(aad), tag_dec, TAG_LEN);

    CHECK(memcmp(recovered, plain, plen) == 0,
          "decrypted text matches original plaintext");
    CHECK(memcmp(tag_enc, tag_dec, TAG_LEN) == 0,
          "GCM authentication tags match");

    /* --- Test 3: tamper detection --- */
    printf("\n--- Test 3: tamper detection ---\n");
    cipher[7] ^= 0xFF;
    uint8_t tag_tampered[16] = {0};
    IMB_AES256_GCM_DEC(mgr, &exp_key, &ctx,
        recovered, cipher, plen,
        iv, aad, sizeof(aad), tag_tampered, TAG_LEN);
    CHECK(memcmp(tag_tampered, tag_enc, TAG_LEN) != 0,
          "tampered ciphertext produces different auth tag");

    /* --- Test 4: AAD tamper --- */
    printf("\n--- Test 4: AAD integrity ---\n");
    cipher[7] ^= 0xFF;  /* restore */
    uint8_t bad_aad[8];
    memcpy(bad_aad, aad, 8);
    bad_aad[0] ^= 0x01;
    uint8_t tag_bad_aad[16] = {0};
    IMB_AES256_GCM_DEC(mgr, &exp_key, &ctx,
        recovered, cipher, plen,
        iv, bad_aad, sizeof(bad_aad), tag_bad_aad, TAG_LEN);
    CHECK(memcmp(tag_bad_aad, tag_enc, TAG_LEN) != 0,
          "modified AAD produces different auth tag (ESP header protected)");

    /* --- Test 5: ISA path verification --- */
    printf("\n--- Test 5: ISA path ---\n");
    CHECK(arch >= IMB_ARCH_SSE,
          "AES-NI instructions available (SSE or better)");
    int has_vaes = (arch >= IMB_ARCH_AVX2) &&
                   (mgr->features & (1ULL << 7)); /* VAES feature bit */
    printf("  arch=%s  VAES=%s  GCM-by%s\n",
           arch < IMB_ARCH_NUM ? arch_names[arch] : "?",
           has_vaes ? "yes" : "no",
           arch == IMB_ARCH_AVX512 ? "32" :
           arch == IMB_ARCH_AVX2   ? "16" : "8");

    /* --- Test 6: multi-buffer burst (shows pipeline efficiency) --- */
    printf("\n--- Test 6: multi-buffer encrypt burst (8 msgs) ---\n");
    #define NBUF 8
    uint8_t bufs[NBUF][64], tags[NBUF][16], ivs[NBUF][IV_LEN];
    for (int i = 0; i < NBUF; i++) {
        memset(bufs[i], i * 17, 64);
        memcpy(ivs[i], iv, IV_LEN);
        ivs[i][11] = i;  /* unique IV per message */
    }
    /* encrypt all 8 in sequence through the same manager —
       intel-ipsec-mb batches internally for SIMD width */
    for (int i = 0; i < NBUF; i++) {
        uint8_t ct[64];
        IMB_AES256_GCM_ENC(mgr, &exp_key, &ctx,
            ct, bufs[i], 48,
            ivs[i], aad, sizeof(aad), tags[i], TAG_LEN);
        /* verify tag is unique per message */
        for (int j = 0; j < i; j++) {
            if (memcmp(tags[i], tags[j], TAG_LEN) == 0) {
                printf("  FAIL: tags[%d] == tags[%d] (should differ)\n", i, j);
                g_fail++; goto burst_done;
            }
        }
    }
    g_pass++;
    printf("  PASS: 8 unique GCM tags (different IV per message)\n");
burst_done:;

    free_mb_mgr(mgr);

    printf("\n╔══════════════════════════════════════════╗\n");
    printf("║  Results: %d passed, %d failed             \n", g_pass, g_fail);
    printf("╚══════════════════════════════════════════╝\n");
    return g_fail > 0 ? 1 : 0;
}
