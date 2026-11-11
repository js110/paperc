package eventreport

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

// These roots are research configuration snapshots. Authenticated root
// publication, rollback protection, credential enrollment, persistence,
// replay prevention, and atomic updates to accepted reports are external.
const (
	ActiveDepth       = 8
	ActiveCapacity    = 1 << ActiveDepth
	domainActiveEmpty = 401
	domainActiveLeaf  = 402
	domainActiveNode  = 403
)

// ActiveCircuit extends the same accountability, region and participant
// credential relation. The active leaf is computed from the same secret that
// the authority credential, task tag, identity link and issuer receipt use.
// The membership root is public but MUST be selected by the verifier.
type ActiveCircuit struct {
	Accountability   AccountabilityCircuit
	ActiveRoot       frontend.Variable `gnark:",public"`
	ActiveSiblings   [ActiveDepth]frontend.Variable
	ActiveDirections [ActiveDepth]frontend.Variable
}

func (c *ActiveCircuit) Define(api frontend.API) error {
	if err := c.Accountability.Define(api); err != nil {
		return err
	}
	d, err := hashFields(api, domainCredential, c.Accountability.Region.Base.Secret)
	if err != nil {
		return err
	}
	current, err := hashFields(api, domainActiveLeaf, d)
	if err != nil {
		return err
	}
	for i := 0; i < ActiveDepth; i++ {
		api.AssertIsBoolean(c.ActiveDirections[i])
		left := api.Select(c.ActiveDirections[i], c.ActiveSiblings[i], current)
		right := api.Select(c.ActiveDirections[i], current, c.ActiveSiblings[i])
		current, err = hashFields(api, domainActiveNode, left, right)
		if err != nil {
			return err
		}
	}
	api.AssertIsEqual(current, c.ActiveRoot)
	return nil
}

// ActiveCredentialID derives the credential digest, not a disclosed identity.
// It is useful to the trusted experimental registrar that maintains the set.
// A real registration protocol must associate this digest with its enrollee.
func ActiveCredentialID(secret *big.Int) (*big.Int, error) {
	if secret == nil || secret.Sign() <= 0 || secret.Cmp(fr.Modulus()) >= 0 {
		return nil, fmt.Errorf("invalid participant secret")
	}
	return nativeHash(n(domainCredential), secret)
}

// ActivePolicy is an immutable in-memory tree snapshot. A nil slot is an empty
// leaf. Slots do not shift on removal, so other paths can be recomputed without
// changing registration indices. Empty trees are valid but cannot admit a proof.
type ActivePolicy struct {
	slots  [ActiveCapacity]*big.Int
	levels [ActiveDepth + 1][]*big.Int
}

// NewActivePolicy creates a trusted snapshot from already enrolled credential
// digests. The registrar must control enrollment; accepting arbitrary digests
// from submitters as verifier policy would defeat revocation.
func NewActivePolicy(credentials []*big.Int) (*ActivePolicy, error) {
	if len(credentials) > ActiveCapacity {
		return nil, fmt.Errorf("too many active credentials")
	}
	var slots [ActiveCapacity]*big.Int
	for i, d := range credentials {
		if d == nil || d.Sign() < 0 || d.Cmp(fr.Modulus()) >= 0 {
			return nil, fmt.Errorf("noncanonical credential digest")
		}
		slots[i] = new(big.Int).Set(d)
	}
	return newActiveSnapshot(slots)
}

func newActiveSnapshot(slots [ActiveCapacity]*big.Int) (*ActivePolicy, error) {
	p := &ActivePolicy{}
	p.levels[0] = make([]*big.Int, ActiveCapacity)
	empty, err := nativeHash(n(domainActiveEmpty))
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	for i, d := range slots {
		if d == nil {
			p.levels[0][i] = new(big.Int).Set(empty)
			continue
		}
		if d.Sign() < 0 || d.Cmp(fr.Modulus()) >= 0 {
			return nil, fmt.Errorf("noncanonical credential digest")
		}
		if _, ok := seen[d.String()]; ok {
			return nil, fmt.Errorf("duplicate credential digest")
		}
		seen[d.String()] = struct{}{}
		p.slots[i] = new(big.Int).Set(d)
		p.levels[0][i], err = nativeHash(n(domainActiveLeaf), d)
		if err != nil {
			return nil, err
		}
	}
	for level := 0; level < ActiveDepth; level++ {
		p.levels[level+1] = make([]*big.Int, len(p.levels[level])/2)
		for i := range p.levels[level+1] {
			p.levels[level+1][i], err = nativeHash(n(domainActiveNode), p.levels[level][2*i], p.levels[level][2*i+1])
			if err != nil {
				return nil, err
			}
		}
	}
	return p, nil
}

func (p *ActivePolicy) index(d *big.Int) int {
	if p == nil || d == nil {
		return -1
	}
	for i, v := range p.slots {
		if v != nil && v.Cmp(d) == 0 {
			return i
		}
	}
	return -1
}

// Root returns a copy, so modifying the result cannot change this snapshot.
func (p *ActivePolicy) Root() *big.Int {
	if p == nil || len(p.levels[ActiveDepth]) != 1 {
		return nil
	}
	return new(big.Int).Set(p.levels[ActiveDepth][0])
}

// Remove returns a new snapshot. It never mutates the old policy, issues a root
// update, prevents verifier rollback, or revokes other credentials for a user.
func (p *ActivePolicy) Remove(credential *big.Int) (*ActivePolicy, error) {
	i := p.index(credential)
	if i < 0 {
		return nil, fmt.Errorf("credential is not active")
	}
	slots := p.slots
	slots[i] = nil
	return newActiveSnapshot(slots)
}

// ActiveAssignment binds an existing accountability witness to the policy
// snapshot. A removed credential cannot obtain a path from this helper. A
// malicious prover need not use this helper; security comes from the circuit.
func (p *ActivePolicy) Assignment(a *AccountabilityCircuit) (*ActiveCircuit, error) {
	if p == nil || a == nil {
		return nil, fmt.Errorf("missing policy or assignment")
	}
	secret, ok := a.Region.Base.Secret.(*big.Int)
	if !ok {
		return nil, fmt.Errorf("expected native participant secret")
	}
	d, err := ActiveCredentialID(secret)
	if err != nil {
		return nil, err
	}
	index := p.index(d)
	if index < 0 {
		return nil, fmt.Errorf("credential is not active")
	}
	out := &ActiveCircuit{Accountability: *a, ActiveRoot: p.Root()}
	for i := 0; i < ActiveDepth; i++ {
		out.ActiveSiblings[i] = new(big.Int).Set(p.levels[i][index^1])
		out.ActiveDirections[i] = index & 1
		index >>= 1
	}
	return out, nil
}

// ActiveVerifier pins the authenticated configuration snapshot and Groth16
// verifier key. It does not fetch or authenticate roots, enforce freshness or
// anti-replay state, or persist acceptances. Those are external requirements.
type ActiveVerifier struct {
	accountability *AccountabilityVerifier
	activeRoot     *big.Int
	vk             groth16.VerifyingKey
}

func NewActiveVerifier(a *AccountabilityVerifier, active *ActivePolicy, vk groth16.VerifyingKey) (*ActiveVerifier, error) {
	if a == nil || a.policy == nil || active == nil || active.Root() == nil || vk == nil {
		return nil, fmt.Errorf("invalid trusted verifier configuration")
	}
	// Reconstruct private copies of both policy and authority configuration.
	region, err := NewRegionPolicy(a.policy.task, a.policy.cells)
	if err != nil {
		return nil, err
	}
	acc, err := NewAccountabilityVerifier(region, a.authority, a.auditor)
	if err != nil {
		return nil, err
	}
	return &ActiveVerifier{accountability: acc, activeRoot: active.Root(), vk: vk}, nil
}

// PublicStatement takes no caller-provided root; all trust anchors come from
// the verifier snapshot. Challenge freshness is checked by a surrounding flow.
func (v *ActiveVerifier) PublicStatement(challenge Challenge, report []byte, nullifier *big.Int, cipher AccountabilityCiphertext) (*ActiveCircuit, error) {
	if v == nil || v.accountability == nil || v.activeRoot == nil {
		return nil, fmt.Errorf("missing verifier")
	}
	a, err := v.accountability.PublicStatement(challenge, report, nullifier, cipher)
	if err != nil {
		return nil, err
	}
	return &ActiveCircuit{Accountability: *a, ActiveRoot: new(big.Int).Set(v.activeRoot)}, nil
}

// Verify checks the proof only; it intentionally does not mean gateway-level
// acceptance, valid encryption, fresh challenge, or durable recording.
func (v *ActiveVerifier) Verify(proof groth16.Proof, challenge Challenge, report []byte, nullifier *big.Int, cipher AccountabilityCiphertext) error {
	if v == nil || v.vk == nil || proof == nil {
		return fmt.Errorf("missing verifier or proof")
	}
	statement, err := v.PublicStatement(challenge, report, nullifier, cipher)
	if err != nil {
		return err
	}
	w, err := frontend.NewWitness(statement, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}
	return groth16.Verify(proof, v.vk, w)
}
