package eventreport

import (
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/sha256"
	"fmt"
)

const kemEnvelopeVersion byte = 1

// SealReportMLKEM encapsulates a fresh ML-KEM-768 shared key for an
// authenticated, pinned recipient public key, derives an AES-256-GCM key and
// encrypts the report. Sender authentication is provided separately by the
// report proof, not by ML-KEM. The entire envelope is passed to ContextField.
func SealReportMLKEM(recipient *mlkem.EncapsulationKey768, plaintext []byte, taskID string) ([]byte, error) {
	if recipient == nil || len(taskID) == 0 || len(taskID) > 256 {
		return nil, fmt.Errorf("invalid recipient or task")
	}
	shared, ciphertext := recipient.Encapsulate()
	key, err := deriveReportKEMKey(shared, ciphertext, taskID)
	if err != nil {
		return nil, err
	}
	sealed, err := SealReport(key, plaintext, taskID)
	if err != nil {
		return nil, err
	}
	result := make([]byte, 0, 1+len(ciphertext)+len(sealed))
	result = append(result, kemEnvelopeVersion)
	result = append(result, ciphertext...)
	result = append(result, sealed...)
	return result, nil
}

// OpenReportMLKEM authenticates and decrypts a complete KEM envelope. The
// gateway binds these exact bytes to the proof; it does not open the envelope.
func OpenReportMLKEM(recipient *mlkem.DecapsulationKey768, envelope []byte, taskID string) ([]byte, error) {
	if recipient == nil || len(taskID) == 0 || len(taskID) > 256 || len(envelope) < 1+mlkem.CiphertextSize768+1 || envelope[0] != kemEnvelopeVersion {
		return nil, fmt.Errorf("invalid KEM envelope")
	}
	ciphertext := envelope[1 : 1+mlkem.CiphertextSize768]
	shared, err := recipient.Decapsulate(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decapsulation failed")
	}
	key, err := deriveReportKEMKey(shared, ciphertext, taskID)
	if err != nil {
		return nil, err
	}
	return OpenReport(key, envelope[1+mlkem.CiphertextSize768:], taskID)
}

func deriveReportKEMKey(shared, ciphertext []byte, taskID string) ([]byte, error) {
	h := sha256.New()
	h.Write([]byte("event-report-kem-salt-v1\x00"))
	h.Write(reportAAD(taskID))
	h.Write(ciphertext)
	return hkdf.Key(sha256.New, shared, h.Sum(nil), "event-report-mlkem768-aes256gcm-v1", 32)
}
