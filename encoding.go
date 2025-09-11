package main

import (
	"bytes"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"strings"
)

const (
	hostnameFileName    = "hostname"
	publicKeyFileName   = "hs_ed25519_public_key"
	secretKeyFileName   = "hs_ed25519_secret_key"
	publicKeyFilePrefix = "== ed25519v1-public: type0 ==\x00\x00\x00"
	secretKeyFilePrefix = "== ed25519v1-secret: type0 ==\x00\x00\x00"
	secretKeyFileLength = 96
)

const onionBase32EncodingCharset = "abcdefghijklmnopqrstuvwxyz234567"

var onionBase32Encoding = base32.NewEncoding(onionBase32EncodingCharset).WithPadding(base32.NoPadding)

// encodeOnionAddress returns the .onion address for the given ed25519 public key,
// as specified in 6. Encoding onion addresses [ONIONADDRESS]
//
// [ONIONADDRESS] https://github.com/torproject/torspec/blob/main/rend-spec-v3.txt
func encodeOnionAddress(publicKey []byte) string {
	version := []byte("\x03")

	// CHECKSUM = H(".onion checksum" | PUBKEY | VERSION)[:2]
	h := sha3.New256()
	h.Write([]byte(".onion checksum"))
	h.Write(publicKey)
	h.Write(version)
	checksum := h.Sum(nil)[:2]

	// onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
	var buf bytes.Buffer
	buf.Write(publicKey)
	buf.Write(checksum)
	buf.Write(version)

	return onionBase32Encoding.EncodeToString(buf.Bytes()) + ".onion"
}

// encodePublicKey returns the content of hs_ed25519_public_key file.
func encodePublicKey(publicKey []byte) []byte {
	buf := make([]byte, 0, 64)
	buf = append(buf, publicKeyFilePrefix...)
	buf = append(buf, publicKey...)
	return buf
}

// encodeSecretKey returns the content of hs_ed25519_secret_key file.
func encodeSecretKey(secretKey []byte) []byte {
	buf := make([]byte, 0, 96)
	buf = append(buf, secretKeyFilePrefix...)

	// From https://gitlab.torproject.org/tpo/core/tor/-/blob/main/src/lib/crypt_ops/crypto_ed25519.h#L27
	//
	//  * Note that we store secret keys in an expanded format that doesn't match
	//  * the format from standard ed25519.  Ed25519 stores a 32-byte value k and
	//  * expands it into a 64-byte H(k), using the first 32 bytes for a multiplier
	//  * of the base point, and second 32 bytes as an input to a hash function
	//  * for deriving r.  But because we implement key blinding, we need to store
	//  * keys in the 64-byte expanded form.
	//
	// Here we hash the secret key to deterministically get the second 32 bytes.
	// Tor also apparently does not clamp private key so do it here as well.
	hs := sha512.Sum512(secretKey)
	copy(hs[:], secretKey)
	hs[0] &= 248
	hs[31] &= 63
	hs[31] |= 64
	buf = append(buf, hs[:]...)
	return buf
}

func decodePublicKey(b []byte) ([]byte, error) {
	b, ok := bytes.CutPrefix(b, []byte(publicKeyFilePrefix))
	if !ok {
		return nil, fmt.Errorf("invalid public key prefix")
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("invalid public key length, must be 32 bytes")
	}
	return b, nil
}

func decodeSecretKey(b []byte) ([]byte, error) {
	b, ok := bytes.CutPrefix(b, []byte(secretKeyFilePrefix))
	if !ok {
		return nil, fmt.Errorf("invalid secret key prefix")
	}
	if len(b) != 64 {
		return nil, fmt.Errorf("invalid secret key length, must be 64 bytes")
	}
	return b[:32], nil
}

// decodePrefixBits returns base32-decoded prefix and number of decoded bits.
func decodePrefixBits(prefix string) ([]byte, int, error) {
	decodedBits := 5 * len(prefix)
	quantums := (len(prefix) + 7) / 8
	prefix += strings.Repeat("a", quantums*8-len(prefix))
	buf := make([]byte, quantums*5)
	_, err := onionBase32Encoding.Decode(buf, []byte(prefix))
	if err != nil {
		return nil, 0, err
	}
	return buf, decodedBits, err
}

// hasPrefixBits returns a function that checks if the input has the specified prefix bits.
func hasPrefixBits(prefix []byte, bits int) func(input []byte) bool {
	if len(prefix) == 0 || len(prefix) > 32 {
		panic("invalid prefix ")
	}
	if bits <= 0 || bits > 256 || bits > len(prefix)*8 {
		panic("invalid bits")
	}

	if bits%8 == 0 {
		return func(b []byte) bool {
			return bytes.HasPrefix(b, prefix)
		}
	}

	prefixBytes := bits / 8
	shift := 8 - (bits % 8)
	tailByte := prefix[prefixBytes] >> shift
	prefix = prefix[:prefixBytes]

	return func(b []byte) bool {
		return len(b) > prefixBytes && // must be long enough to check tail byte
			bytes.Equal(b[:prefixBytes], prefix) &&
			b[prefixBytes]>>shift == tailByte
	}
}
