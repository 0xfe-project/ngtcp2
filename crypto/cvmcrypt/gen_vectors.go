//go:build ignore

// crypto/cvmcrypt/gen_vectors.go
//
// Generates the known-answer vectors hardcoded in cvmcrypt_test.c.
//
// The point of this file is that it is NOT our code. Every expected value in
// the test comes from Go's standard library (crypto/aes, crypto/cipher,
// crypto/hkdf), so a failure in the backend cannot be "the test agrees with
// the implementation because they are the same mistake".
//
// Stdlib only, so it runs with GO111MODULE=off and needs no module.
//
// Upstream ngtcp2 ships no AEAD/HKDF vectors for any backend — crypto/
// cryptotest.c only covers retry-token verification — so these had to be
// produced rather than borrowed.
//
//	cd crypto/cvmcrypt && GO111MODULE=off go run gen_vectors.go
//
// Output is C initialisers. Regenerate only when an input changes; the
// hardcoded values are the regression contract.

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	// RFC 8446 §7.1: HkdfLabel = length(2) || "tls13 " + label(1+n) || context(0)
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0) // empty context
	out, err := hkdf.Expand(sha256.New, secret, string(info), length)
	if err != nil {
		panic(err)
	}
	return out
}

func aeadVector(name string, newAEAD func([]byte) (cipher.AEAD, error),
	key, nonce, aad, pt []byte) {
	a, err := newAEAD(key)
	if err != nil {
		panic(err)
	}
	out := a.Seal(nil, nonce, pt, aad)
	ct, tag := out[:len(pt)], out[len(pt):]
	fmt.Printf("\n/* %s */\n", name)
	fmt.Printf("key   %s\n", hex.EncodeToString(key))
	fmt.Printf("nonce %s\n", hex.EncodeToString(nonce))
	fmt.Printf("aad   %s\n", hex.EncodeToString(aad))
	fmt.Printf("pt    %s\n", hex.EncodeToString(pt))
	fmt.Printf("ct    %s\n", hex.EncodeToString(ct))
	fmt.Printf("tag   %s\n", hex.EncodeToString(tag))
}

func main() {
	// --- RFC 9001 A.1: initial secrets for a known DCID -------------------
	dcid, _ := hex.DecodeString("8394c8f03e515708")
	salt, _ := hex.DecodeString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

	// RFC 9001 A.1: initial_secret is the HKDF-Extract output, NOT an
	// expand. hkdf.Key() would run extract-then-expand and give a different
	// 32 bytes; that cost one debugging round here.
	initial, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		panic(err)
	}
	clientIS := hkdfExpandLabel(initial, "client in", 32)
	serverIS := hkdfExpandLabel(initial, "server in", 32)

	fmt.Printf("/* RFC 9001 A.1, derived here with Go's crypto/hkdf */\n")
	fmt.Printf("initial_secret        %s\n", hex.EncodeToString(initial))
	fmt.Printf("client_initial_secret %s\n", hex.EncodeToString(clientIS))
	fmt.Printf("server_initial_secret %s\n", hex.EncodeToString(serverIS))
	for _, d := range []struct {
		name string
		n    int
	}{
		{"key", 16}, {"iv", 12}, {"hp", 16},
	} {
		label := map[string]string{"key": "quic key", "iv": "quic iv", "hp": "quic hp"}[d.name]
		fmt.Printf("client_%-3s %s\n", d.name, hex.EncodeToString(hkdfExpandLabel(clientIS, label, d.n)))
		fmt.Printf("server_%-3s %s\n", d.name, hex.EncodeToString(hkdfExpandLabel(serverIS, label, d.n)))
	}

	// --- RFC 5869 Test Case 1 (HKDF-SHA256) --------------------------------
	ikm := make([]byte, 22)
	for i := range ikm {
		ikm[i] = 0x0b
	}
	salt2, _ := hex.DecodeString("000102030405060708090a0b0c")
	info2, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	prk, err := hkdf.Extract(sha256.New, ikm, salt2)
	if err != nil {
		panic(err)
	}
	okm, err := hkdf.Expand(sha256.New, prk, string(info2), 42)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\n/* RFC 5869 test case 1 */\n")
	fmt.Printf("tc1_ikm %s\n", hex.EncodeToString(ikm))
	fmt.Printf("tc1_salt %s\n", hex.EncodeToString(salt2))
	fmt.Printf("tc1_info %s\n", hex.EncodeToString(info2))
	fmt.Printf("tc1_prk %s\n", hex.EncodeToString(prk))
	fmt.Printf("tc1_okm %s\n", hex.EncodeToString(okm))

	// --- AEAD, both families QUIC allows ----------------------------------
	key128, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	key256, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	nonce, _ := hex.DecodeString("000102030405060708090a0b")
	aad, _ := hex.DecodeString("c0ff000000000001") // a QUIC-looking header
	pt := []byte("the quick brown fox jumps over the lazy dog")

	aeadVector("AES-128-GCM", func(k []byte) (cipher.AEAD, error) {
		b, err := aes.NewCipher(k)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(b)
	}, key128, nonce, aad, pt)

	aeadVector("AES-256-GCM", func(k []byte) (cipher.AEAD, error) {
		b, err := aes.NewCipher(k)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(b)
	}, key256, nonce, aad, pt)

	// --- header protection masks -----------------------------------------
	// AES: mask = AES-ECB(sample)[0:5]. ChaCha20: mask = chacha20 block with
	// counter/nonce taken from the sample, first 5 bytes.
	hpKey128, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	sample, _ := hex.DecodeString("d1b1c98dd7689fb8ec11d242b123dc9b")
	b, _ := aes.NewCipher(hpKey128)
	block := make([]byte, 16)
	b.Encrypt(block, sample)
	fmt.Printf("\n/* RFC 9001 A.2 sample, AES-ECB via Go's crypto/aes */\n")
	fmt.Printf("hp_aes128_sample %s\n", hex.EncodeToString(sample))
	fmt.Printf("hp_aes128_mask   %s\n", hex.EncodeToString(block[:5]))

	/*
	 * ChaCha20-Poly1305 and the ChaCha20 header-protection mask are not
	 * generated here: Go's implementation is in x/crypto, and pulling a
	 * module dependency into a C repository for a dev script is not worth
	 * it. Those two vectors come from a Python reference implementation
	 * that was itself checked against RFC 8439 §2.3.2 before being used;
	 * the values are in cvmcrypt_test.c with that provenance noted there.
	 */
}
