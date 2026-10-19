/*
 * crypto/cvmcrypt/cvmcrypt.c
 *
 * The cvmcrypt backend for ngtcp2: the crypto primitives QUIC needs, and the
 * TLS plumbing that carries handshake messages through CRYPTO frames.
 *
 * This is a peer of crypto/picotls and crypto/ossl, not a fork of either. The
 * contract it satisfies lives in ngtcp2_crypto.h and crypto/shared.h; the
 * generic half — derive_and_install_*, update_key, tokens — is in shared.c
 * and is backend-independent, so nothing of it is repeated here.
 *
 * Three shape notes, each the reason a line below is shorter than its picotls
 * counterpart:
 *
 *   * cvmcrypt's AEAD takes the full 12-byte nonce per call. picotls keeps a
 *     static IV inside the context and XORs the nonce in and out around every
 *     operation; here the caller's nonce already includes that XOR, so there
 *     is no state to restore and no window where the IV is "temporarily wrong".
 *
 *   * cvmcrypt's AEAD writes ciphertext and tag separately, so
 *     ngtcp2_crypto_encrypt()/decrypt() split ngtcp2's contiguous buffer at
 *     plaintextlen / ciphertextlen - taglen.
 *
 *   * cvmcrypt's header protection is one primitive for both families (the
 *     keystream block over the 16-byte sample), so hp_mask() has no branch on
 *     AES vs ChaCha20 — that decision was made when the ctx was created.
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#include <assert.h>
#include <string.h>

#include <ngtcp2/ngtcp2_crypto.h>

#include "rt.h"

#include <cvmcrypt/cvmcrypt.h>

#include "tls/tls.h"

#include "ngtcp2_macro.h"
#include "shared.h"

/*
 * The TLS side is still a skeleton (cvm_tls_handle_message returns
 * TLS_ERROR_NOT_AVAILABLE), so the two functions that touch it report a clean
 * failure instead of pretending. Everything above them is complete and is
 * what the KAT in crypto/cvmcrypt_test.c exercises.
 */

/* ------------------------------------------------------------------ */
/* descriptors                                                          */
/* ------------------------------------------------------------------ */

/*
 * shared.c provides ngtcp2_crypto_md_init and ngtcp2_crypto_cipher_init
 * because neither needs anything from the backend. aead_init does: the
 * overhead is the tag size, which only the AEAD implementation knows.
 */
ngtcp2_crypto_aead *ngtcp2_crypto_aead_init(ngtcp2_crypto_aead *aead,
                                            void *aead_native_handle) {
    aead->native_handle = aead_native_handle;
    aead->max_overhead =
        (size_t)cvmcrypt_aead_tag_size((CvmcryptAeadAlg const *)aead_native_handle);
    return aead;
}

ngtcp2_crypto_aead *ngtcp2_crypto_aead_aes_128_gcm(ngtcp2_crypto_aead *aead) {
    return ngtcp2_crypto_aead_init(aead, (void *)&cvmcrypt_aead_aes128gcm);
}

ngtcp2_crypto_aead *ngtcp2_crypto_aead_aes_256_gcm(ngtcp2_crypto_aead *aead) {
    return ngtcp2_crypto_aead_init(aead, (void *)&cvmcrypt_aead_aes256gcm);
}

ngtcp2_crypto_aead *ngtcp2_crypto_aead_chacha20_poly1305(ngtcp2_crypto_aead *aead) {
    return ngtcp2_crypto_aead_init(aead, (void *)&cvmcrypt_aead_chacha20poly1305);
}

/* Retry packet integrity is AEAD_AES_128_GCM with a fixed key, whatever the
 * handshake negotiates (RFC 9001 §5.8). */
ngtcp2_crypto_aead *ngtcp2_crypto_aead_retry(ngtcp2_crypto_aead *aead) {
    return ngtcp2_crypto_aead_init(aead, (void *)&cvmcrypt_aead_aes128gcm);
}

ngtcp2_crypto_md *ngtcp2_crypto_md_sha256(ngtcp2_crypto_md *md) {
    md->native_handle = (void *)&cvmcrypt_md_sha256;
    return md;
}

ngtcp2_crypto_md *ngtcp2_crypto_md_sha384(ngtcp2_crypto_md *md) {
    md->native_handle = (void *)&cvmcrypt_md_sha384;
    return md;
}

/*
 * Initial packets always use AES-128-GCM + SHA-256 + AES-128-ECB
 * (RFC 9001 §5.2), regardless of what the handshake later negotiates.
 */
ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_initial(ngtcp2_crypto_ctx *ctx) {
    ngtcp2_crypto_aead_init(&ctx->aead, (void *)&cvmcrypt_aead_aes128gcm);
    ctx->md.native_handle = (void *)&cvmcrypt_md_sha256;
    ctx->hp.native_handle = (void *)&cvmcrypt_cipher_aes128;
    ctx->max_encryption = 0;
    ctx->max_decryption_failure = 0;
    return ctx;
}

/* Map the negotiated TLS suite onto (aead, md, hp). */
static int suite_to_ctx(ngtcp2_crypto_ctx *ctx, CvmTlsCipherSuite const *suite) {
    if (suite == NULL) {
        return -1;
    }

    switch (suite->id) {
    case 0x1301: /* TLS_AES_128_GCM_SHA256 */
        ngtcp2_crypto_aead_init(&ctx->aead, (void *)&cvmcrypt_aead_aes128gcm);
        ctx->md.native_handle = (void *)&cvmcrypt_md_sha256;
        ctx->hp.native_handle = (void *)&cvmcrypt_cipher_aes128;
        break;
    case 0x1302: /* TLS_AES_256_GCM_SHA384 */
        ngtcp2_crypto_aead_init(&ctx->aead, (void *)&cvmcrypt_aead_aes256gcm);
        ctx->md.native_handle = (void *)&cvmcrypt_md_sha384;
        ctx->hp.native_handle = (void *)&cvmcrypt_cipher_aes256;
        break;
    case 0x1303: /* TLS_CHACHA20_POLY1305_SHA256 */
        ngtcp2_crypto_aead_init(&ctx->aead, (void *)&cvmcrypt_aead_chacha20poly1305);
        ctx->md.native_handle = (void *)&cvmcrypt_md_sha256;
        ctx->hp.native_handle = (void *)&cvmcrypt_cipher_chacha20;
        break;
    default:
        return -1;
    }

    ctx->max_encryption = 0;
    ctx->max_decryption_failure = 0;
    return 0;
}

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_tls(ngtcp2_crypto_ctx *ctx, void *tls) {
    CvmTlsCipherSuite const *suite = cvm_tls_get_cipher_suite((CvmTls *)tls);
    if (suite_to_ctx(ctx, suite) != 0) {
        return NULL;
    }
    return ctx;
}

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_tls_early(ngtcp2_crypto_ctx *ctx, void *tls) {
    /* 0-RTT uses the same AEAD/md/hp as the 1-RTT suite. */
    return ngtcp2_crypto_ctx_tls(ctx, tls);
}

/* ------------------------------------------------------------------ */
/* descriptor queries (backend-provided: only the implementation knows)  */
/* ------------------------------------------------------------------ */

size_t ngtcp2_crypto_md_hashlen(const ngtcp2_crypto_md *md) {
    return cvmcrypt_md_digest_size((CvmcryptMdAlg const *)md->native_handle);
}

size_t ngtcp2_crypto_aead_keylen(const ngtcp2_crypto_aead *aead) {
    return cvmcrypt_aead_key_size((CvmcryptAeadAlg const *)aead->native_handle);
}

size_t ngtcp2_crypto_aead_noncelen(const ngtcp2_crypto_aead *aead) {
    return cvmcrypt_aead_nonce_size((CvmcryptAeadAlg const *)aead->native_handle);
}

/* ------------------------------------------------------------------ */
/* AEAD                                                                 */
/* ------------------------------------------------------------------ */

int ngtcp2_crypto_aead_ctx_encrypt_init(ngtcp2_crypto_aead_ctx *aead_ctx,
                                        const ngtcp2_crypto_aead *aead,
                                        const uint8_t *key, size_t noncelen) {
    (void)noncelen;
    aead_ctx->native_handle = NULL;

    CvmcryptAeadCtx *ctx = rt_mem_alloc(sizeof(*ctx));
    if (ctx == NULL) {
        return -1;
    }
    if (!cvmcrypt_aead_init(ctx, (CvmcryptAeadAlg const *)aead->native_handle, key)) {
        rt_mem_free(ctx);
        return -1;
    }
    aead_ctx->native_handle = ctx;
    return 0;
}

int ngtcp2_crypto_aead_ctx_decrypt_init(ngtcp2_crypto_aead_ctx *aead_ctx,
                                        const ngtcp2_crypto_aead *aead,
                                        const uint8_t *key, size_t noncelen) {
    /* The context is symmetric; seal and open are separate entry points. */
    return ngtcp2_crypto_aead_ctx_encrypt_init(aead_ctx, aead, key, noncelen);
}

void ngtcp2_crypto_aead_ctx_free(ngtcp2_crypto_aead_ctx *aead_ctx) {
    if (aead_ctx->native_handle) {
        cvmcrypt_aead_clear((CvmcryptAeadCtx *)aead_ctx->native_handle);
        rt_mem_free(aead_ctx->native_handle);
        aead_ctx->native_handle = NULL;
    }
}

/* ------------------------------------------------------------------ */
/* header protection cipher                                             */
/* ------------------------------------------------------------------ */

int ngtcp2_crypto_cipher_ctx_encrypt_init(ngtcp2_crypto_cipher_ctx *cipher_ctx,
                                          const ngtcp2_crypto_cipher *cipher,
                                          const uint8_t *key) {
    cipher_ctx->native_handle = NULL;

    CvmcryptCipherCtx *ctx = rt_mem_alloc(sizeof(*ctx));
    if (ctx == NULL) {
        return -1;
    }
    if (!cvmcrypt_cipher_init(ctx, (CvmcryptCipherAlg const *)cipher->native_handle, key)) {
        rt_mem_free(ctx);
        return -1;
    }
    cipher_ctx->native_handle = ctx;
    return 0;
}

void ngtcp2_crypto_cipher_ctx_free(ngtcp2_crypto_cipher_ctx *cipher_ctx) {
    if (cipher_ctx->native_handle) {
        cvmcrypt_cipher_clear((CvmcryptCipherCtx *)cipher_ctx->native_handle);
        rt_mem_free(cipher_ctx->native_handle);
        cipher_ctx->native_handle = NULL;
    }
}

/* ------------------------------------------------------------------ */
/* HKDF                                                                 */
/* ------------------------------------------------------------------ */

int ngtcp2_crypto_hkdf_extract(uint8_t *dest, const ngtcp2_crypto_md *md,
                               const uint8_t *secret, size_t secretlen,
                               const uint8_t *salt, size_t saltlen) {
    /* ngtcp2's "secret" is HKDF's IKM, and "salt" its salt. */
    if (!cvmcrypt_hkdf_extract((CvmcryptMdAlg const *)md->native_handle, dest, salt,
                               saltlen, secret, secretlen)) {
        return -1;
    }
    return 0;
}

int ngtcp2_crypto_hkdf_expand(uint8_t *dest, size_t destlen,
                              const ngtcp2_crypto_md *md, const uint8_t *secret,
                              size_t secretlen, const uint8_t *info, size_t infolen) {
    if (!cvmcrypt_hkdf_expand((CvmcryptMdAlg const *)md->native_handle, dest, destlen,
                              secret, info, infolen)) {
        return -1;
    }
    (void)secretlen;
    return 0;
}

int ngtcp2_crypto_hkdf(uint8_t *dest, size_t destlen, const ngtcp2_crypto_md *md,
                       const uint8_t *secret, size_t secretlen, const uint8_t *salt,
                       size_t saltlen, const uint8_t *info, size_t infolen) {
    CvmcryptMdAlg const *alg = (CvmcryptMdAlg const *)md->native_handle;
    uint8_t prk[CVMCRYPT_SHA512_DIGEST_SIZE];

    if (cvmcrypt_md_digest_size(alg) > sizeof(prk)) {
        return -1;
    }
    if (!cvmcrypt_hkdf_extract(alg, prk, salt, saltlen, secret, secretlen)) {
        return -1;
    }
    if (!cvmcrypt_hkdf_expand(alg, dest, destlen, prk, info, infolen)) {
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* packet protection                                                    */
/* ------------------------------------------------------------------ */

int ngtcp2_crypto_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                          const ngtcp2_crypto_aead_ctx *aead_ctx,
                          const uint8_t *plaintext, size_t plaintextlen,
                          const uint8_t *nonce, size_t noncelen, const uint8_t *aad,
                          size_t aadlen) {
    CvmcryptAeadCtx *ctx = aead_ctx->native_handle;
    usize taglen = cvmcrypt_aead_tag_size(aead->native_handle);

    (void)aead;
    (void)noncelen; /* always 12 for QUIC */

    /* ngtcp2 expects ciphertext followed by the tag in one buffer. */
    if (!cvmcrypt_aead_seal(ctx, nonce, aad, aadlen, plaintext, plaintextlen, dest,
                            dest + plaintextlen)) {
        return -1;
    }
    (void)taglen;
    return 0;
}

int ngtcp2_crypto_decrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                          const ngtcp2_crypto_aead_ctx *aead_ctx,
                          const uint8_t *ciphertext, size_t ciphertextlen,
                          const uint8_t *nonce, size_t noncelen, const uint8_t *aad,
                          size_t aadlen) {
    CvmcryptAeadCtx *ctx = aead_ctx->native_handle;
    usize const taglen = cvmcrypt_aead_tag_size(aead->native_handle);

    (void)noncelen;

    if (ciphertextlen < taglen) {
        return -1;
    }

    usize const ctlen = ciphertextlen - taglen;
    if (!cvmcrypt_aead_open(ctx, nonce, aad, aadlen, ciphertext, ctlen, dest,
                            ciphertext + ctlen)) {
        return -1;
    }
    return 0;
}

int ngtcp2_crypto_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                          const ngtcp2_crypto_cipher_ctx *hp_ctx,
                          const uint8_t *sample) {
    (void)hp;

    /*
     * One primitive covers both families: AES-ECB over the sample, or the
     * ChaCha20 block whose counter and nonce the sample encodes. ngtcp2 reads
     * the first NGTCP2_HP_MASKLEN bytes; the whole block is written because
     * that is what the primitive produces.
     */
    if (!cvmcrypt_cipher_keystream((CvmcryptCipherCtx *)hp_ctx->native_handle, sample,
                                   dest)) {
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* randomness                                                           */
/* ------------------------------------------------------------------ */

int ngtcp2_crypto_random(uint8_t *data, size_t datalen) {
    if (!cvmcrypt_random(data, datalen)) {
        return -1;
    }
    return 0;
}

int ngtcp2_crypto_get_path_challenge_data_cb(ngtcp2_conn *conn, uint8_t *data,
                                             void *user_data) {
    (void)conn;
    (void)user_data;
    return ngtcp2_crypto_random(data, NGTCP2_PATH_CHALLENGE_DATALEN);
}

int ngtcp2_crypto_get_path_challenge_data2_cb(ngtcp2_conn *conn,
                                              ngtcp2_path_challenge_data *data,
                                              void *user_data) {
    (void)conn;
    (void)user_data;
    return ngtcp2_crypto_random(data->data, NGTCP2_PATH_CHALLENGE_DATALEN);
}

/* ------------------------------------------------------------------ */
/* TLS plumbing                                                         */
/* ------------------------------------------------------------------ */

ngtcp2_encryption_level ngtcp2_crypto_cvmcrypt_from_epoch(size_t epoch) {
    switch (epoch) {
    case 0:
        return NGTCP2_ENCRYPTION_LEVEL_INITIAL;
    case 1:
        return NGTCP2_ENCRYPTION_LEVEL_0RTT;
    case 2:
        return NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE;
    case 3:
        return NGTCP2_ENCRYPTION_LEVEL_1RTT;
    default:
        return NGTCP2_ENCRYPTION_LEVEL_INITIAL;
    }
}

size_t ngtcp2_crypto_cvmcrypt_from_ngtcp2_encryption_level(
    ngtcp2_encryption_level level) {
    switch (level) {
    case NGTCP2_ENCRYPTION_LEVEL_INITIAL:
        return 0;
    case NGTCP2_ENCRYPTION_LEVEL_0RTT:
        return 1;
    case NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE:
        return 2;
    case NGTCP2_ENCRYPTION_LEVEL_1RTT:
        return 3;
    }
    return 0;
}

int ngtcp2_crypto_read_write_crypto_data(ngtcp2_conn *conn,
                                         ngtcp2_encryption_level encryption_level,
                                         const uint8_t *data, size_t datalen) {
    (void)conn;
    (void)encryption_level;
    (void)data;
    (void)datalen;

    /*
     * Blocked on cvmcrypt: cvm_tls_handle_message() — the record-less
     * handshake entry point QUIC needs — is still a stub returning
     * TLS_ERROR_NOT_AVAILABLE. Wiring this without it would mean inventing a
     * TLS state machine here, in a file that has no business owning one.
     *
     * When that lands, this function is: check the epoch against
     * cvm_tls_get_read_epoch(), call cvm_tls_handle_message() with
     * epoch_offsets[5], then hand each non-empty epoch slice to
     * ngtcp2_conn_submit_crypto_data().
     */
    return NGTCP2_ERR_CALLBACK_FAILURE;
}

int ngtcp2_crypto_set_local_transport_params(void *tls, const uint8_t *buf,
                                             size_t len) {
    (void)tls;
    (void)buf;
    (void)len;
    /* Same blocker: the QUIC transport-parameters extension is carried by the
     * TLS layer, which does not implement it yet. */
    return -1;
}

int ngtcp2_crypto_set_remote_transport_params(ngtcp2_conn *conn, void *tls) {
    (void)conn;
    (void)tls;
    return -1;
}
