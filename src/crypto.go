package network

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"
)

func Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("encrypt: key must be 32 bytes (got %d)", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("encrypt: aes.NewCipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("encrypt: cipher.NewGCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("encrypt: nonce rand: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Return [12 bytes of Nonce] + [Encrypted Data] + [16 bytes of Auth Tag]
	//Auth tag is alredy inside the ciphertext
	out := make([]byte, 0, len(nonce)+len(ciphertext))
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

func Decrypt(key []byte, data []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("decrypt: key must be 32 bytes (got %d)", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("decrypt: aes.NewCipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("decrypt: cipher.NewGCM: %w", err)
	}

	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, errors.New("decrypt: data too short")
	}

	nonce := data[:ns]
	ciphertext := data[ns:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: gcm.Open: %w", err)
	}
	return plaintext, nil
}

type Session struct {
	Key       []byte
	CreatedAt time.Time
}

func (s *Session) RotateKey() error {
	newKey := make([]byte, 32) // AES-256
	if _, err := rand.Read(newKey); err != nil {
		return err
	}
	s.Key = newKey
	s.CreatedAt = time.Now()
	return nil
}
