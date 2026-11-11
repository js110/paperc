package eventreport

import (
	"crypto/mlkem"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

// RegionGateway adds the RegionCircuit relation to the same single-instance,
// volatile challenge and deduplication model used by Gateway. The verification
// key, authority and RegionPolicy must come from authenticated verifier-side
// configuration. Task ID must not be reused with a different policy in a live
// deployment. This prototype does not implement persistent/distributed state.
type RegionGateway struct {
	base         *Gateway
	policy       *RegionPolicy
	recipientKey *mlkem.DecapsulationKey768
}

// NewRegionGateway reconstructs the trusted policy from a copy of its cells;
// no policy, root, or verification key can be supplied by Submit. The caller
// must provide a verification key generated from RegionCircuit, not Circuit.
func NewRegionGateway(authority []byte, policy *RegionPolicy, vk groth16.VerifyingKey, recipientKey *mlkem.DecapsulationKey768) (*RegionGateway, error) {
	if policy == nil || recipientKey == nil {
		return nil, fmt.Errorf("invalid region policy or recipient key")
	}
	recipientSnapshot, err := mlkem.NewDecapsulationKey768(recipientKey.Bytes())
	if err != nil {
		return nil, fmt.Errorf("invalid recipient key: %w", err)
	}
	snapshot, err := NewRegionPolicy(policy.task, policy.cells)
	if err != nil {
		return nil, err
	}
	base, err := NewGateway(authority, snapshot.task, vk)
	if err != nil {
		return nil, err
	}
	return &RegionGateway{base: base, policy: snapshot, recipientKey: recipientSnapshot}, nil
}

// Issue returns a challenge stored in this gateway. The supplied timestamp is
// from the trusted gateway clock, in Unix seconds.
func (g *RegionGateway) Issue(now, ttl int64) (Challenge, error) {
	return g.base.Issue(now, ttl)
}

// Submit accepts an authenticated report while discarding its plaintext.
// Call SubmitAndOpen to process the accepted report.
func (g *RegionGateway) Submit(nonce string, envelope []byte, nullifier *big.Int, proof groth16.Proof, now int64) error {
	_, err := g.SubmitAndOpen(nonce, envelope, nullifier, proof, now)
	return err
}

// SubmitAndOpen verifies a proof bound to the actual versioned ML-KEM and AES-GCM
// envelope. The envelope contains its own encryption nonce and authentication
// tag; nonce is the gateway's separate challenge, and nullifier is the
// task-scoped deduplication tag. Here the gateway is also the recipient: after
// the proof verifies, it decapsulates and checks the AEAD tag using its key.
// Key establishment, issuer observation and trusted time are external.
// Rejection does not consume a live challenge or an unused nullifier. A valid
// proof atomically consumes the challenge and records the nullifier in memory,
// then returns the plaintext. Report persistence is not included: durable
// acceptance requires a transaction covering report storage and replay state.
func (g *RegionGateway) SubmitAndOpen(nonce string, envelope []byte, nullifier *big.Int, proof groth16.Proof, now int64) ([]byte, error) {
	g.base.mu.Lock()
	defer g.base.mu.Unlock()
	challenge, exists := g.base.pending[nonce]
	if !exists {
		return nil, ErrUnknownChallenge
	}
	if now <= 0 || now >= challenge.ExpiresAt {
		return nil, ErrExpiredChallenge
	}
	// Version 1 includes an ML-KEM ciphertext and a versioned AES-GCM envelope
	// with a 12-byte nonce and a 16-byte authentication tag.
	// Length/version checks alone are not authentication.
	if len(envelope) < 1+mlkem.CiphertextSize768+1+12+16 || envelope[0] != kemEnvelopeVersion {
		return nil, fmt.Errorf("invalid ciphertext envelope")
	}
	if nullifier == nil || nullifier.Sign() < 0 || nullifier.Cmp(fr.Modulus()) >= 0 {
		return nil, fmt.Errorf("invalid nullifier")
	}
	if proof == nil {
		return nil, ErrInvalidProof
	}
	key := nullifier.String()
	if _, exists := g.base.usedNullifiers[key]; exists {
		return nil, ErrDuplicateReport
	}
	statement, err := g.policy.PublicStatement(g.base.authority, challenge, envelope, nullifier)
	if err != nil {
		return nil, fmt.Errorf("invalid public statement: %w", err)
	}
	public, err := frontend.NewWitness(statement, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return nil, fmt.Errorf("invalid public witness: %w", err)
	}
	if err := groth16.Verify(proof, g.base.vk, public); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidProof, err)
	}
	plaintext, err := OpenReportMLKEM(g.recipientKey, envelope, g.policy.task.ID)
	if err != nil {
		return nil, fmt.Errorf("ciphertext authentication failed: %w", err)
	}
	delete(g.base.pending, nonce)
	g.base.usedNullifiers[key] = struct{}{}
	return plaintext, nil
}
