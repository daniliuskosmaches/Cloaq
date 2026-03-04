package network

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

func Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("Encrypt: key must be 32 bytes (got %d)", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Encrypt: aes.NewCipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Encrypt: cipher.NewGCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("Encrypt: nonce rand: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Return nonce || ciphertext
	out := make([]byte, 0, len(nonce)+len(ciphertext))
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

func Decrypt(key []byte, data []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("Decrypt: key must be 32 bytes (got %d)", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Decrypt: aes.NewCipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Decrypt: cipher.NewGCM: %w", err)
	}

	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, errors.New("Decrypt: data too short")
	}

	nonce := data[:ns]
	ciphertext := data[ns:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("Decrypt: gcm.Open: %w", err)
	}
	return plaintext, nil
}
