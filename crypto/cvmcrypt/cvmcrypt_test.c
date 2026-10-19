/*
 * crypto/cvmcrypt/cvmcrypt_test.c
 *
 * Known-answer tests for the cvmcrypt backend.
 *
 * Why this file exists: upstream ngtcp2 ships no AEAD/HKDF vectors for any
 * backend — crypto/cryptotest.c only covers retry-token verification — so a
 * backend that derives the wrong key produces a library that links, passes
 * the upstream suite, and fails only against a real peer.
 *
 * Every expected value below comes from somewhere other than this code:
 *
 *   RFC 9001 A.1 initial secrets   Go crypto/hkdf AND Python hmac, which
 *                                  agree with each other and with the RFC
 *   RFC 5869 test case 1           same two implementations
 *   AES-128/256-GCM ciphertext     Go crypto/cipher (ct || tag layout)
 *   AES header protection mask     Go crypto/aes; openssl enc agrees
 *   ChaCha20 header protection     a Python reference checked against
 *                                  RFC 8439 §2.3.2 before being used
 *
 * crypto/cvmcrypt/gen_vectors.go regenerates the ones Go can produce; the
 * ChaCha20 ones come from the Python reference described in its footer.
 */

#define MUNIT_ENABLE_ASSERT_ALIASES

#include "munit.h"

#include <string.h>

#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_cvmcrypt.h>

#include "shared.h"

/* cvmcrypt */
#include <cvmcrypt/cvmcrypt.h>

/* ------------------------------------------------------------------ */
/* helpers                                                              */
/* ------------------------------------------------------------------ */

static void hex2bin(uint8_t *out, size_t n, const char *hex) {
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        char pair[3] = {hex[2 * i], hex[2 * i + 1], 0};
        sscanf(pair, "%x", &v);
        out[i] = (uint8_t)v;
    }
}

static int bytes_eq(const uint8_t *got, const char *want_hex, size_t n) {
    uint8_t want[128];
    if (n > sizeof(want)) {
        return 0;
    }
    hex2bin(want, n, want_hex);
    return memcmp(got, want, n) == 0;
}

/* ------------------------------------------------------------------ */
/* RFC 9001 A.1: initial secrets from a known DCID                      */
/* ------------------------------------------------------------------ */

/*
 * client_dcid = 8394c8f03e515708. The values are the RFC's own: the Go and
 * Python derivations above reproduce its published bytes exactly, which is
 * how we know the label encoding (RFC 8446 §7.1) is right and not merely
 * self-consistent.
 */
static void test_initial_secrets(void) {
    static const char *DCID = "8394c8f03e515708";

    ngtcp2_cid dcid;
    ngtcp2_cid_init(&dcid, (const uint8_t *)"", 0);
    dcid.datalen = 8;
    hex2bin(dcid.data, dcid.datalen, DCID);

    uint8_t rx[32], tx[32], initial[32];

    munit_assert_int(0, ==,
                     ngtcp2_crypto_derive_initial_secrets(
                         rx, tx, initial, NGTCP2_PROTO_VER_V1, &dcid,
                         NGTCP2_CRYPTO_SIDE_CLIENT));

    munit_assert_true(bytes_eq(
        initial,
        "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44", 32));
    munit_assert_true(bytes_eq(
        tx, /* client_initial_secret */
        "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea", 32));
    munit_assert_true(bytes_eq(
        rx, /* server_initial_secret */
        "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b", 32));
}

static void test_packet_protection_key(void) {
    uint8_t secret[32];
    hex2bin(secret, sizeof(secret),
            "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");

    ngtcp2_crypto_ctx ctx;
    ngtcp2_crypto_ctx_initial(&ctx);

    uint8_t key[32], iv[32], hp[32];

    munit_assert_int(0, ==,
                     ngtcp2_crypto_derive_packet_protection_key(
                         key, iv, hp, NGTCP2_PROTO_VER_V1, &ctx.aead, &ctx.md,
                         secret, sizeof(secret)));

    munit_assert_true(bytes_eq(key, "1f369613dd76d5467730efcbe3b1a22d", 16));
    munit_assert_true(bytes_eq(iv, "fa044b2f42a3fd3b46fb255c", 12));
    munit_assert_true(bytes_eq(hp, "9f50449e04a0e810283a1e9933adedd2", 16));
}

/* ------------------------------------------------------------------ */
/* RFC 5869 test case 1, through the ngtcp2 entry points                */
/* ------------------------------------------------------------------ */

static void test_hkdf_rfc5869_tc1(void) {
    uint8_t ikm[22], salt[13], info[10];

    memset(ikm, 0x0b, sizeof(ikm));
    hex2bin(salt, sizeof(salt), "000102030405060708090a0b0c");
    hex2bin(info, sizeof(info), "f0f1f2f3f4f5f6f7f8f9");

    ngtcp2_crypto_md md;
    ngtcp2_crypto_md_sha256(&md);

    uint8_t prk[32], okm[42];

    munit_assert_int(0, ==,
                     ngtcp2_crypto_hkdf_extract(prk, &md, ikm, sizeof(ikm), salt,
                                                sizeof(salt)));
    munit_assert_true(bytes_eq(
        prk, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", 32));

    munit_assert_int(0, ==,
                     ngtcp2_crypto_hkdf_expand(okm, sizeof(okm), &md, prk, sizeof(prk),
                                               info, sizeof(info)));
    munit_assert_true(
        bytes_eq(okm,
                 "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                 "34007208d5b887185865",
                 42));

    /* One-shot must agree with extract-then-expand. */
    uint8_t okm2[42];
    munit_assert_int(0, ==,
                     ngtcp2_crypto_hkdf(okm2, sizeof(okm2), &md, ikm, sizeof(ikm), salt,
                                        sizeof(salt), info, sizeof(info)));
    munit_assert_memory_equal(sizeof(okm2), okm, okm2);
}

/* ------------------------------------------------------------------ */
/* AEAD through ngtcp2's entry points                                   */
/* ------------------------------------------------------------------ */

/*
 * The layout is the thing being tested here, not AES. ngtcp2 hands one
 * contiguous buffer to the backend and expects ciphertext followed by the tag
 * on the way out; cvmcrypt keeps them separate, so the split at
 * plaintextlen / ciphertextlen - taglen is ours to get right.
 */
static void test_aead_roundtrip(void) {
    uint8_t key[32], nonce[12], aad[8], pt[64], ct[64 + 16], back[64];

    for (size_t i = 0; i < sizeof(key); i++) {
        key[i] = (uint8_t)i;
    }
    for (size_t i = 0; i < sizeof(nonce); i++) {
        nonce[i] = (uint8_t)(0x10 + i);
    }
    for (size_t i = 0; i < sizeof(aad); i++) {
        aad[i] = (uint8_t)(0xc0 + i);
    }
    for (size_t i = 0; i < sizeof(pt); i++) {
        pt[i] = (uint8_t)(i * 3 + 1);
    }

    ngtcp2_crypto_ctx ctx;
    ngtcp2_crypto_ctx_initial(&ctx);

    ngtcp2_crypto_aead_ctx aead_ctx;
    munit_assert_int(0, ==, ngtcp2_crypto_aead_ctx_encrypt_init(&aead_ctx, &ctx.aead,
                                                                key, sizeof(nonce)));

    munit_assert_int(0, ==,
                     ngtcp2_crypto_encrypt(ct, &ctx.aead, &aead_ctx, pt, sizeof(pt),
                                           nonce, sizeof(nonce), aad, sizeof(aad)));

    munit_assert_memory_not_equal(sizeof(pt), pt, ct);

    munit_assert_int(
        0, ==,
        ngtcp2_crypto_decrypt(back, &ctx.aead, &aead_ctx, ct, sizeof(ct), nonce,
                              sizeof(nonce), aad, sizeof(aad)));
    munit_assert_memory_equal(sizeof(pt), pt, back);

    /* One flipped ciphertext bit must be rejected. */
    ct[9] ^= 0x04;
    munit_assert_int(-1, ==,
                     ngtcp2_crypto_decrypt(back, &ctx.aead, &aead_ctx, ct, sizeof(ct),
                                           nonce, sizeof(nonce), aad, sizeof(aad)));
    ct[9] ^= 0x04;

    /* Truncating below the tag length must be refused, not read past. */
    munit_assert_int(-1, ==,
                     ngtcp2_crypto_decrypt(back, &ctx.aead, &aead_ctx, ct, 8, nonce,
                                           sizeof(nonce), aad, sizeof(aad)));

    ngtcp2_crypto_aead_ctx_free(&aead_ctx);
}

/* Go crypto/cipher produced ct || tag for these exact inputs. */
static void test_aead_matches_go_vectors(void) {
    static const char *PT = "74686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67";
    static const char *AAD = "c0ff000000000001";
    static const char *NONCE = "000102030405060708090a0b";
    size_t const ptlen = 43;

    uint8_t pt[64], aad[8], nonce[12], out[64 + 16];

    hex2bin(pt, ptlen, PT);
    hex2bin(aad, sizeof(aad), AAD);
    hex2bin(nonce, sizeof(nonce), NONCE);

    struct {
        ngtcp2_crypto_aead *(*sel)(ngtcp2_crypto_aead *);
        const char *key;
        size_t keylen;
        const char *ct;
        const char *tag;
    } const cases[] = {
        {ngtcp2_crypto_aead_aes_128_gcm, "000102030405060708090a0b0c0d0e0f", 16,
         "e704c2ee176e9e3720f203f859d41e28d54962c63998908695019e5b71368218edc1fb9b9"
         "5facec3249b6e",
         "d8639a251dadc0836241b3c992949ec1"},
        {ngtcp2_crypto_aead_aes_256_gcm,
         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 32,
         "336ab33bb490ab78e661f5f9de9e164de5b9ff149a0e320c4b478af3781b20c669758e90ce"
         "bb6bb810cb18",
         "cfa78f2305fe7ec9913385487bf1872a"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint8_t key[32];
        hex2bin(key, cases[i].keylen, cases[i].key);

        ngtcp2_crypto_aead aead;
        cases[i].sel(&aead);

        ngtcp2_crypto_aead_ctx aead_ctx;
        munit_assert_int(0, ==, ngtcp2_crypto_aead_ctx_encrypt_init(&aead_ctx, &aead, key,
                                                                    sizeof(nonce)));
        munit_assert_int(0, ==,
                         ngtcp2_crypto_encrypt(out, &aead, &aead_ctx, pt, ptlen, nonce,
                                               sizeof(nonce), aad, sizeof(aad)));
        munit_assert_true(bytes_eq(out, cases[i].ct, ptlen));
        munit_assert_true(bytes_eq(out + ptlen, cases[i].tag, 16));
        ngtcp2_crypto_aead_ctx_free(&aead_ctx);
    }
}

/* ------------------------------------------------------------------ */
/* header protection                                                    */
/* ------------------------------------------------------------------ */

static void test_hp_mask(void) {
    uint8_t sample[16], key[32], mask[16];

    /* AES-128: Go crypto/aes, and openssl enc -aes-128-ecb -nopad, agree. */
    hex2bin(key, 16, "000102030405060708090a0b0c0d0e0f");
    hex2bin(sample, sizeof(sample), "d1b1c98dd7689fb8ec11d242b123dc9b");

    ngtcp2_crypto_cipher hp;
    ngtcp2_crypto_cipher_init(&hp, (void *)&cvmcrypt_cipher_aes128);

    ngtcp2_crypto_cipher_ctx hp_ctx;
    munit_assert_int(0, ==,
                     ngtcp2_crypto_cipher_ctx_encrypt_init(&hp_ctx, &hp, key));
    munit_assert_int(0, ==, ngtcp2_crypto_hp_mask(mask, &hp, &hp_ctx, sample));
    munit_assert_true(bytes_eq(mask, "21a22dfb17", NGTCP2_HP_MASKLEN));
    ngtcp2_crypto_cipher_ctx_free(&hp_ctx);

    /*
     * ChaCha20: sample's first four bytes are the block counter (little
     * endian), the rest the nonce. Value from the Python reference checked
     * against RFC 8439 §2.3.2.
     */
    hex2bin(key, 32,
            "25a282b9e82f06f221488917a4fc8f1b4b0f3b8ff1d0a5e0f9d3a1c7bd9e34a6");
    hex2bin(sample, sizeof(sample), "5e5cd55c41f69080575d7999c25a5bfb");

    ngtcp2_crypto_cipher hp2;
    ngtcp2_crypto_cipher_init(&hp2, (void *)&cvmcrypt_cipher_chacha20);

    ngtcp2_crypto_cipher_ctx hp_ctx2;
    munit_assert_int(0, ==,
                     ngtcp2_crypto_cipher_ctx_encrypt_init(&hp_ctx2, &hp2, key));
    munit_assert_int(0, ==, ngtcp2_crypto_hp_mask(mask, &hp2, &hp_ctx2, sample));
    munit_assert_true(bytes_eq(mask, "b54937be4b", NGTCP2_HP_MASKLEN));
    ngtcp2_crypto_cipher_ctx_free(&hp_ctx2);
}

/* ------------------------------------------------------------------ */
/* descriptor queries                                                   */
/* ------------------------------------------------------------------ */

static void test_descriptors(void) {
    ngtcp2_crypto_ctx ctx;
    ngtcp2_crypto_ctx_initial(&ctx);

    munit_assert_size(16, ==, ngtcp2_crypto_aead_keylen(&ctx.aead));
    munit_assert_size(12, ==, ngtcp2_crypto_aead_noncelen(&ctx.aead));
    munit_assert_size(32, ==, ngtcp2_crypto_md_hashlen(&ctx.md));
    munit_assert_size(16, ==, ctx.aead.max_overhead);

    ngtcp2_crypto_aead aead256;
    ngtcp2_crypto_aead_aes_256_gcm(&aead256);
    munit_assert_size(32, ==, ngtcp2_crypto_aead_keylen(&aead256));

    ngtcp2_crypto_md md384;
    ngtcp2_crypto_md_sha384(&md384);
    munit_assert_size(48, ==, ngtcp2_crypto_md_hashlen(&md384));
}

/* ------------------------------------------------------------------ */
/* randomness                                                           */
/* ------------------------------------------------------------------ */

static void fill_deterministic(uint8_t *out, size_t len, void *user) {
    const uint8_t *seed = user;
    for (size_t i = 0; i < len; i++) {
        out[i] = (uint8_t)(seed[0] + i);
    }
}

static void test_random(void) {
    uint8_t buf[8];
    uint8_t seed[1] = {0x20};

    /* No source installed: fail, do not invent zeros. */
    cvmcrypt_random_set_source(NULL, NULL);
    munit_assert_int(-1, ==, ngtcp2_crypto_random(buf, sizeof(buf)));

    cvmcrypt_random_set_source(fill_deterministic, seed);
    munit_assert_int(0, ==, ngtcp2_crypto_random(buf, sizeof(buf)));
    munit_assert_uint8(0x20, ==, buf[0]);
    munit_assert_uint8(0x27, ==, buf[7]);

    cvmcrypt_random_set_source(NULL, NULL);
}

/* ------------------------------------------------------------------ */

/* Each case needs its wrap_ generator emitted; that is what
 * munit_void_test_decl does, and ngtcp2's munit fork requires it. */
munit_void_test_decl(test_initial_secrets)
munit_void_test_decl(test_packet_protection_key)
munit_void_test_decl(test_hkdf_rfc5869_tc1)
munit_void_test_decl(test_aead_roundtrip)
munit_void_test_decl(test_aead_matches_go_vectors)
munit_void_test_decl(test_hp_mask)
munit_void_test_decl(test_descriptors)
munit_void_test_decl(test_random)

static const MunitTest tests[] = {
    munit_void_test(test_initial_secrets),
    munit_void_test(test_packet_protection_key),
    munit_void_test(test_hkdf_rfc5869_tc1),
    munit_void_test(test_aead_roundtrip),
    munit_void_test(test_aead_matches_go_vectors),
    munit_void_test(test_hp_mask),
    munit_void_test(test_descriptors),
    munit_void_test(test_random),
    munit_test_end(),
};

const MunitSuite cvmcrypt_suite = {
    .prefix = "/cvmcrypt",
    .tests = tests,
};

int main(int argc, char *argv[]) {
    return munit_suite_main(&cvmcrypt_suite, NULL, argc, argv);
}
