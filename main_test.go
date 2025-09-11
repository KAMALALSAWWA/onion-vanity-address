package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/AlexanderYastrebov/onion-vanity-address/internal/assert"
	"github.com/AlexanderYastrebov/onion-vanity-address/internal/require"
)

func TestFixture(t *testing.T) {
	const fixture = "onionjifniegtjbbifet65goa2siqubne6n2qfhiksryfvsbdhdl5zid.onion"

	secretKeyBytes, err := os.ReadFile(filepath.Join("testdata", fixture, "hs_ed25519_secret_key"))
	require.NoError(t, err)

	secretKeyBytes = bytes.TrimPrefix(secretKeyBytes, []byte(secretKeyFilePrefix))
	require.Equal(t, 64, len(secretKeyBytes))

	publicKeyBytes, err := os.ReadFile(filepath.Join("testdata", fixture, "hs_ed25519_public_key"))
	require.NoError(t, err)

	expectedPublicKey := bytes.TrimPrefix(publicKeyBytes, []byte(publicKeyFilePrefix))
	require.Equal(t, 32, len(expectedPublicKey))

	secretKey := secretKeyBytes[:32]
	t.Logf("Secret key: %s", onionBase32Encoding.EncodeToString(secretKey))

	publicKey, err := publicKeyFor(secretKey)
	require.NoError(t, err)

	t.Logf("Public key: %s", onionBase32Encoding.EncodeToString(publicKey))

	assert.Equal(t, expectedPublicKey, publicKey)

	onionAddress := encodeOnionAddress(publicKey)
	assert.Equal(t, fixture, onionAddress)

	hostnameBytes, err := os.ReadFile(filepath.Join("testdata", fixture, "hostname"))
	require.NoError(t, err)

	assert.Equal(t, []byte(fixture+"\n"), hostnameBytes)
}

func TestDecodeBase32PrefixBits(t *testing.T) {
	tests := []struct {
		input         string
		expectedBytes []byte
		expectedBits  int
	}{
		{
			input:         "7",
			expectedBytes: []byte{0b11111_000, 0, 0, 0, 0},
			expectedBits:  5,
		},
		{
			input:         "77",
			expectedBytes: []byte{0b11111_111, 0b11_00000_0, 0, 0, 0},
			expectedBits:  10,
		},
		{
			input:         "b",
			expectedBytes: []byte{0b00001_000, 0, 0, 0, 0},
			expectedBits:  5,
		},
		{
			input:         "ay",
			expectedBytes: []byte{0b00000_110, 0b00_00000_0, 0, 0, 0},
			expectedBits:  10,
		},
		{
			input:         "abc",
			expectedBytes: []byte{0b00000_000, 0b01_00010_0, 0, 0, 0},
			expectedBits:  15,
		},
		{
			input:         "ayay",
			expectedBytes: []byte{0b00000_110, 0b00_00000_1, 0b1000_0000, 0, 0},
			expectedBits:  20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			b, n, err := decodePrefixBits(tt.input)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedBits, n)
			assert.Equal(t, tt.expectedBytes, b)
		})
	}
}
