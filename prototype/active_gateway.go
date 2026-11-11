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

// ActiveGateway enforces the active-credential relation together with the
// accountability, region, report and replay relations. Updates and acceptance
// share one process-local lock. State, root history and revocations are volatile;
// authenticated configuration, restart recovery and persistence are external.
type ActiveGateway struct {
	account   *AccountabilityGateway
	verifier  *ActiveVerifier
	policy    *ActivePolicy
	revision  uint64
	seenRoots map[string]struct{}
	revoked   map[string]struct{}
}

// NewActiveGateway snapshots all trusted configuration. vk must be generated
// from ActiveCircuit. revision is an externally authenticated monotonic version.
func NewActiveGateway(authority []byte, region *RegionPolicy, auditor ed.PointAffine, active *ActivePolicy, revision uint64, vk groth16.VerifyingKey, recipient *mlkem.DecapsulationKey768) (*ActiveGateway, error) {
	if active == nil || revision == 0 {
		return nil, fmt.Errorf("invalid initial active configuration")
	}
	snapshot, err := newActiveSnapshot(active.slots)
	if err != nil {
		return nil, err
	}
	account, err := NewAccountabilityGateway(authority, region, auditor, vk, recipient)
	if err != nil {
		return nil, err
	}
	verifier, err := NewActiveVerifier(account.verifier, snapshot, vk)
	if err != nil {
		return nil, err
	}
	return &ActiveGateway{account: account, verifier: verifier, policy: snapshot, revision: revision, seenRoots: map[string]struct{}{snapshot.Root().String(): {}}, revoked: make(map[string]struct{})}, nil
}
func (g *ActiveGateway) Issue(now, ttl int64) (Challenge, error) { return g.account.Issue(now, ttl) }

// ActiveSnapshot returns the accepted version and a copy of its root.
func (g *ActiveGateway) ActiveSnapshot() (uint64, *big.Int) {
	g.account.region.base.mu.Lock()
	defer g.account.region.base.mu.Unlock()
	return g.revision, g.policy.Root()
}

// UpdateActivePolicy is a trusted-administrator API, not a signed distribution
// or access-control protocol. A later version may add fresh credentials or
// remove existing ones. This instance rejects prior roots, version rollback,
// and restoration of a credential it has observed being removed. New instances
// lose this history; no cross-restart anti-rollback guarantee is implied.
func (g *ActiveGateway) UpdateActivePolicy(next *ActivePolicy, revision uint64) error {
	if g == nil || g.account == nil || next == nil {
		return fmt.Errorf("missing gateway or active policy")
	}
	snapshot, err := newActiveSnapshot(next.slots)
	if err != nil {
		return err
	}
	g.account.region.base.mu.Lock()
	defer g.account.region.base.mu.Unlock()
	if revision <= g.revision {
		return fmt.Errorf("active revision must increase")
	}
	if _, seen := g.seenRoots[snapshot.Root().String()]; seen {
		return fmt.Errorf("active root already used")
	}
	for _, d := range snapshot.slots {
		if d != nil {
			if _, removed := g.revoked[d.String()]; removed {
				return fmt.Errorf("revoked credential cannot be restored in this instance")
			}
		}
	}
	verifier, err := NewActiveVerifier(g.account.verifier, snapshot, g.account.region.base.vk)
	if err != nil {
		return err
	}
	for _, d := range g.policy.slots {
		if d != nil && snapshot.index(d) < 0 {
			g.revoked[d.String()] = struct{}{}
		}
	}
	g.policy = snapshot
	g.verifier = verifier
	g.revision = revision
	g.seenRoots[snapshot.Root().String()] = struct{}{}
	return nil
}

// SubmitAndOpen verifies against the current active-root snapshot while holding
// the update lock. It consumes state only after both proof and report AEAD pass.
// The returned accepted record binds the audited identity ciphertext to the
// serialized ActiveCircuit proof/public witness. Callers must not mutate inputs
// concurrently with the call; copies prevent later mutations changing evidence.
func (g *ActiveGateway) SubmitAndOpen(nonce string, envelope []byte, nullifier *big.Int, cipher AccountabilityCiphertext, proof []byte, now int64) ([]byte, *AcceptedAccountabilityRecord, error) {
	if g == nil || g.account == nil || g.account.region == nil {
		return nil, nil, fmt.Errorf("missing gateway")
	}
	if len(proof) == 0 || len(proof) > 1<<20 {
		return nil, nil, ErrInvalidProof
	}
	proofCopy := append([]byte(nil), proof...)
	envelopeCopy := append([]byte(nil), envelope...)
	var nullifierCopy *big.Int
	if nullifier != nil {
		nullifierCopy = new(big.Int).Set(nullifier)
	}
	base := g.account.region.base
	base.mu.Lock()
	defer base.mu.Unlock()
	challenge, ok := base.pending[nonce]
	if !ok {
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
	if _, exists := base.usedNullifiers[key]; exists {
		return nil, nil, ErrDuplicateReport
	}
	statement, err := g.verifier.PublicStatement(challenge, envelopeCopy, nullifierCopy, cipher)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid public statement: %w", err)
	}
	public, err := frontend.NewWitness(statement, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return nil, nil, err
	}
	detached := groth16.NewProof(ecc.BN254)
	reader := bytes.NewReader(proofCopy)
	if _, err = detached.ReadFrom(reader); err != nil || reader.Len() != 0 {
		return nil, nil, ErrInvalidProof
	}
	if err = groth16.Verify(detached, base.vk, public); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidProof, err)
	}
	var witness bytes.Buffer
	if _, err = public.WriteTo(&witness); err != nil {
		return nil, nil, err
	}
	plaintext, err := OpenReportMLKEM(g.account.region.recipientKey, envelopeCopy, g.account.region.policy.task.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("ciphertext authentication failed: %w", err)
	}
	record := &AcceptedAccountabilityRecord{ciphertext: cipher, auditor: g.account.verifier.auditor, proof: proofCopy, witness: append([]byte(nil), witness.Bytes()...)}
	delete(base.pending, nonce)
	base.usedNullifiers[key] = struct{}{}
	return plaintext, record, nil
}
