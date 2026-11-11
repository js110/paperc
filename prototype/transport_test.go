package eventreport

import (
	"bytes"
	"testing"
)

func TestEncryptedReportEnvelope(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	msg := []byte("temperature 22")
	a, err := SealReport(key, msg, "task-A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := SealReport(key, msg, "task-A")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("distinct encryptions unexpectedly identical")
	}
	opened, err := OpenReport(key, a, "task-A")
	if err != nil || !bytes.Equal(opened, msg) {
		t.Fatalf("decryption failed: %v", err)
	}
	if _, err := OpenReport(key, a, "task-B"); err == nil {
		t.Fatal("wrong task accepted")
	}
	wrong := bytes.Repeat([]byte{8}, 32)
	if _, err := OpenReport(wrong, a, "task-A"); err == nil {
		t.Fatal("wrong key accepted")
	}
	corrupt := append([]byte(nil), a...)
	corrupt[len(corrupt)-1] ^= 1
	if _, err := OpenReport(key, corrupt, "task-A"); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	if _, err := OpenReport(key, a[:5], "task-A"); err == nil {
		t.Fatal("truncated envelope accepted")
	}
}
