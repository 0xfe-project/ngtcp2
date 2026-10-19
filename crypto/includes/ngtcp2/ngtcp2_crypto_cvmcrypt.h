/*
 * crypto/includes/ngtcp2/ngtcp2_crypto_cvmcrypt.h
 *
 * The cvmcrypt backend's own surface, a peer of ngtcp2_crypto_picotls.h.
 *
 * crypto/shared.h declares only the subset its generic helpers call; the rest
 * of what a backend provides — the algorithm selectors and the descriptor
 * constructor — is declared by the backend itself. That is why this file
 * exists rather than the test reaching into the implementation.
 *
 * Anything a caller must not use is not here.
 */

#ifndef NGTCP2_CRYPTO_CVMCRYPT_H
#define NGTCP2_CRYPTO_CVMCRYPT_H

#include <ngtcp2/ngtcp2_crypto.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Algorithm selectors. shared.h declares the 128-bit AES and SHA-256 ones
 * because its own helpers use them; the rest are ours to declare.
 */
NGTCP2_EXTERN ngtcp2_crypto_aead *
ngtcp2_crypto_aead_aes_256_gcm(ngtcp2_crypto_aead *aead);

NGTCP2_EXTERN ngtcp2_crypto_aead *
ngtcp2_crypto_aead_chacha20_poly1305(ngtcp2_crypto_aead *aead);

NGTCP2_EXTERN ngtcp2_crypto_md *ngtcp2_crypto_md_sha384(ngtcp2_crypto_md *md);

/* Descriptor constructor: fills native_handle and max_overhead (the tag
 * size), which only the AEAD implementation knows. */
NGTCP2_EXTERN ngtcp2_crypto_aead *
ngtcp2_crypto_aead_init(ngtcp2_crypto_aead *aead, void *aead_native_handle);

NGTCP2_EXTERN ngtcp2_crypto_cipher *
ngtcp2_crypto_cipher_init(ngtcp2_crypto_cipher *cipher,
                          void *cipher_native_handle);

/*
 * Encryption level <-> TLS epoch. Epoch 0 initial, 1 0-RTT, 2 handshake,
 * 3 1-RTT; the same numbering cvmcrypt uses for its traffic key callback.
 */
NGTCP2_EXTERN ngtcp2_encryption_level
ngtcp2_crypto_cvmcrypt_from_epoch(size_t epoch);

NGTCP2_EXTERN size_t ngtcp2_crypto_cvmcrypt_from_ngtcp2_encryption_level(
    ngtcp2_encryption_level level);

/*
 * Wire cvmcrypt's traffic key callback into a TLS context. Without this the
 * handshake completes and no keys ever reach ngtcp2.
 */
struct CvmTlsContext;
NGTCP2_EXTERN int
ngtcp2_crypto_cvmcrypt_configure_client_context(struct CvmTlsContext *ctx);
NGTCP2_EXTERN int
ngtcp2_crypto_cvmcrypt_configure_server_context(struct CvmTlsContext *ctx);

#ifdef __cplusplus
}
#endif

#endif /* !defined(NGTCP2_CRYPTO_CVMCRYPT_H) */
