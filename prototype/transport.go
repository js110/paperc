package eventreport

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

// SealReport encrypts a report using a separately established 256-bit key.
// The returned versioned ciphertext, not plaintext, is bound to the proof.
// Nonces are randomly generated for each encryption; key management is external.
func SealReport(key, plaintext []byte, taskID string) ([]byte, error) {
	if len(key) != 32 || len(taskID) == 0 || len(taskID) > 256 {
		return nil, fmt.Errorf("invalid encryption parameters")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := append([]byte{1}, nonce...)
	return gcm.Seal(out, nonce, plaintext, reportAAD(taskID)), nil
}

// OpenReport authenticates and decrypts an envelope for the given task.
func OpenReport(key, envelope []byte, taskID string) ([]byte, error) {
	if len(key) != 32 || len(taskID) == 0 || len(taskID) > 256 {
		return nil, fmt.Errorf("invalid encryption parameters")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	n := gcm.NonceSize()
	if len(envelope) < 1+n+gcm.Overhead() || envelope[0] != 1 {
		return nil, fmt.Errorf("invalid envelope")
	}
	return gcm.Open(nil, envelope[1:1+n], envelope[1+n:], reportAAD(taskID))
}

func reportAAD(taskID string) []byte {
	b := []byte("event-report-aead-v1\x00")
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(taskID)))
	b = append(b, length[:]...)
	return append(b, taskID...)
}
