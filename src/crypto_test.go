package network

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read key: %v", err)
	}

	orig := []byte("hello cloaq - aes-gcm test message")

	enc, err := Encrypt(key, orig)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	dec, err := Decrypt(key, enc)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(dec, orig) {
		t.Fatalf("plaintext mismatch: got %q want %q", dec, orig)
	}
}
