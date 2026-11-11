package eventreport

import (
	"bytes"
	"crypto/mlkem"
	"testing"
)

func TestMLKEMReportEnvelope(t *testing.T) {
	recipient, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	another, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("private sensor observation")
	a, err := SealReportMLKEM(recipient.EncapsulationKey(), msg, "task-A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := SealReportMLKEM(recipient.EncapsulationKey(), msg, "task-A")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two envelopes identical")
	}
	got, err := OpenReportMLKEM(recipient, a, "task-A")
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("open: %v", err)
	}
	if _, err = OpenReportMLKEM(another, a, "task-A"); err == nil {
		t.Fatal("wrong recipient accepted")
	}
	if _, err = OpenReportMLKEM(recipient, a, "task-B"); err == nil {
		t.Fatal("wrong task accepted")
	}
	for _, i := range []int{1, 1 + mlkem.CiphertextSize768, len(a) - 1} {
		forged := append([]byte(nil), a...)
		forged[i] ^= 1
		if _, err = OpenReportMLKEM(recipient, forged, "task-A"); err == nil {
			t.Fatalf("tampering at %d accepted", i)
		}
	}
	if _, err = OpenReportMLKEM(recipient, a[:20], "task-A"); err == nil {
		t.Fatal("truncated envelope accepted")
	}
}
