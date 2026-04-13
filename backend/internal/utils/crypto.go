package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"os"
)

var encryptionKey []byte

func init() {
	key := os.Getenv("ENCRYPTION_KEY")
	if key == "" {
		key = "seku-default-encryption-key-32b!" // 32 bytes for AES-256
	}
	// Ensure key is exactly 32 bytes
	if len(key) < 32 {
		padded := make([]byte, 32)
		copy(padded, key)
		encryptionKey = padded
	} else {
		encryptionKey = []byte(key[:32])
	}
}

// Encrypt encrypts plaintext using AES-256-GCM.
func Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return "enc:" + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts ciphertext encrypted with Encrypt.
// If the value is not encrypted (no "enc:" prefix), it returns the original value.
func Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	// If not encrypted, return as-is (backward compatible)
	if len(ciphertext) < 4 || ciphertext[:4] != "enc:" {
		return ciphertext, nil
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext[4:])
	if err != nil {
		return ciphertext, nil // Return original if decode fails
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return ciphertext, nil
	}

	nonce, encrypted := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return ciphertext, nil // Return original if decrypt fails
	}

	return string(plaintext), nil
}

// IsEncrypted checks if a value has already been encrypted.
func IsEncrypted(value string) bool {
	return len(value) >= 4 && value[:4] == "enc:"
}
