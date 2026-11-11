package eventreport

import (
	"bytes"
	"crypto/mlkem"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	ed "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

// AccountabilityGateway accepts AccountabilityCircuit proofs using the same
// single-process, volatile challenge and nullifier state as RegionGateway.
// It also acts as the report's ML-KEM/AES-GCM recipient. Configuration and
// verification key are trusted; durable, distributed acceptance is not provided.
type AccountabilityGateway struct {
	region   *RegionGateway
	verifier *AccountabilityVerifier
}

// NewAccountabilityGateway snapshots verifier-authorized CA, region, auditor,
// and recipient key. vk must be the key for AccountabilityCircuit; it must
// never be selected by a report submitter.
func NewAccountabilityGateway(authority []byte, policy *RegionPolicy, auditor ed.PointAffine, vk groth16.VerifyingKey, recipient *mlkem.DecapsulationKey768) (*AccountabilityGateway, error) {
	region, err := NewRegionGateway(authority, policy, vk, recipient)
	if err != nil {
		return nil, err
	}
	verifier, err := NewAccountabilityVerifier(region.policy, region.base.authority, auditor)
	if err != nil {
		return nil, err
	}
	return &AccountabilityGateway{region: region, verifier: verifier}, nil
}
func (g *AccountabilityGateway) Issue(now, ttl int64) (Challenge, error) {
	return g.region.Issue(now, ttl)
}

// AcceptedAccountabilityRecord retains private snapshots of the verified
// proof's identity ciphertext and public witness. Returned byte slices are
// copies. This is in-memory evidence, not durable or tamper-evident storage.
// A real investigator must additionally enforce opening authorization and map
// the recovered point to a separately managed authenticated registration.
type AcceptedAccountabilityRecord struct {
	ciphertext AccountabilityCiphertext
	auditor    ed.PointAffine
	proof      []byte
	witness    []byte
}

func (r *AcceptedAccountabilityRecord) CiphertextSnapshot() AccountabilityCiphertext {
	return r.ciphertext
}
func (r *AcceptedAccountabilityRecord) ProofBytes() []byte { return append([]byte(nil), r.proof...) }
func (r *AcceptedAccountabilityRecord) PublicWitnessBytes() []byte {
	return append([]byte(nil), r.witness...)
}
func (r *AcceptedAccountabilityRecord) OpenIdentity(secret *big.Int) (ed.PointAffine, error) {
	if r == nil || len(r.proof) == 0 || len(r.witness) == 0 {
		return ed.PointAffine{}, fmt.Errorf("missing verified record")
	}
	return OpenAccountabilityCiphertext(secret, r.auditor, r.ciphertext)
}

// SubmitAndOpen reconstructs the full statement from verifier configuration,
// stored challenge, received envelope, nullifier, and received identity
// ciphertext. It snapshots the ciphertext, public statement, and proof;
// then verifies the detached proof and authenticates the actual report AEAD.
// Only after both succeed does it atomically consume the nonce/nullifier and
// return plaintext and an immutable-by-API accepted identity record. Callers
// must not mutate their inputs concurrently with this method.
func (g *AccountabilityGateway) SubmitAndOpen(nonce string, envelope []byte, nullifier *big.Int, cipher AccountabilityCiphertext, proof []byte, now int64) ([]byte, *AcceptedAccountabilityRecord, error) {
	if g == nil || g.region == nil || g.verifier == nil {
		return nil, nil, fmt.Errorf("missing gateway")
	}
	// Copy the received data before building any statement or opening it.
	// Bound proof parsing independently of any network framing layer.
	if len(proof) == 0 || len(proof) > 1<<20 {
		return nil, nil, ErrInvalidProof
	}
	proofCopy := append([]byte(nil), proof...)
	envelopeCopy := append([]byte(nil), envelope...)
	var nullifierCopy *big.Int
	if nullifier != nil {
		nullifierCopy = new(big.Int).Set(nullifier)
	}
	g.region.base.mu.Lock()
	defer g.region.base.mu.Unlock()
	challenge, exists := g.region.base.pending[nonce]
	if !exists {
		return nil, nil, ErrUnknownChallenge
	}
	if now <= 0 || now >= challenge.ExpiresAt {
		return nil, nil, ErrExpiredChallenge
	}
	if len(envelopeCopy) < 1+mlkem.CiphertextSize768+1+12+16 || envelopeCopy[0] != kemEnvelopeVersion {
		return nil, nil, fmt.Errorf("invalid ciphertext envelope")
	}
	if nullifierCopy == nil || nullifierCopy.Sign() < 0 || nullifierCopy.Cmp(fr.Modulus()) >= 0 {
		return nil, nil, fmt.Errorf("invalid nullifier")
	}
	key := nullifierCopy.String()
	if _, exists := g.region.base.usedNullifiers[key]; exists {
		return nil, nil, ErrDuplicateReport
	}
	statement, err := g.verifier.PublicStatement(challenge, envelopeCopy, nullifierCopy, cipher)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid public statement: %w", err)
	}
	public, err := frontend.NewWitness(statement, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return nil, nil, fmt.Errorf("invalid public witness: %w", err)
	}
	var wb bytes.Buffer
	// Verify the same immutable serialized proof later attached to the record.
	detached := groth16.NewProof(ecc.BN254)
	reader := bytes.NewReader(proofCopy)
	if _, err = detached.ReadFrom(reader); err != nil || reader.Len() != 0 {
		return nil, nil, fmt.Errorf("%w: malformed proof encoding", ErrInvalidProof)
	}
	if err = groth16.Verify(detached, g.region.base.vk, public); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidProof, err)
	}
	if _, err = public.WriteTo(&wb); err != nil {
		return nil, nil, fmt.Errorf("serialize public witness: %w", err)
	}
	plaintext, err := OpenReportMLKEM(g.region.recipientKey, envelopeCopy, g.region.policy.task.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("ciphertext authentication failed: %w", err)
	}
	record := &AcceptedAccountabilityRecord{ciphertext: cipher, auditor: g.verifier.auditor, proof: proofCopy, witness: append([]byte(nil), wb.Bytes()...)}
	delete(g.region.base.pending, nonce)
	g.region.base.usedNullifiers[key] = struct{}{}
	return plaintext, record, nil
}
