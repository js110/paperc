package eventreport

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	nativetwistededwards "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

var (
	ErrUnknownChallenge = errors.New("unknown or consumed challenge")
	ErrExpiredChallenge = errors.New("expired challenge")
	ErrDuplicateReport  = errors.New("task nullifier already used")
	ErrInvalidProof     = errors.New("invalid proof")
)

// Gateway is a single-process, single-task research harness. Its mutex makes
// proof acceptance, challenge consumption and task-scoped deduplication one
// atomic transition inside this instance. State is volatile: a durable or
// distributed store would require an independent transactional implementation.
// The authority, task, circuit verification key, and time source are trusted
// configuration; Task.ID must identify one immutable deduplication scope.
type Gateway struct {
	mu             sync.Mutex
	authority      []byte
	task           Task
	vk             groth16.VerifyingKey
	pending        map[string]Challenge
	usedNullifiers map[string]struct{}
}

// NewGateway takes a snapshot of the verifier-authorized task and authority.
// A verification key is selected by the caller, never by a reporting vehicle.
func NewGateway(authority []byte, task Task, vk groth16.VerifyingKey) (*Gateway, error) {
	if err := task.Validate(); err != nil {
		return nil, err
	}
	if len(authority) != 32 || vk == nil {
		return nil, fmt.Errorf("invalid authority or verification key")
	}
	// SetBytes alone accepts noncanonical encodings and points off the curve.
	// Require a canonical, nonzero point of the prime-order subgroup before
	// passing bytes to gnark's witness decoder. This does not replace trusted
	// key enrollment or an authenticated verifier configuration.
	var authorityPoint, orderMultiple nativetwistededwards.PointAffine
	if _, err := authorityPoint.SetBytes(authority); err != nil || !authorityPoint.IsOnCurve() || authorityPoint.IsZero() {
		return nil, fmt.Errorf("invalid authority point")
	}
	encoded := authorityPoint.Bytes()
	params := nativetwistededwards.GetEdwardsCurve()
	orderMultiple.ScalarMultiplication(&authorityPoint, &params.Order)
	if !bytes.Equal(encoded[:], authority) || !orderMultiple.IsZero() {
		return nil, fmt.Errorf("noncanonical or non-subgroup authority point")
	}
	return &Gateway{
		authority:      append([]byte(nil), authority...),
		task:           task,
		vk:             vk,
		pending:        make(map[string]Challenge),
		usedNullifiers: make(map[string]struct{}),
	}, nil
}

// Issue creates a fresh 256-bit challenge; timestamps use Unix seconds. The
// current time supplied to Issue and Submit must come from a trusted clock.
func (g *Gateway) Issue(now, ttl int64) (Challenge, error) {
	if now <= 0 || ttl <= 0 || ttl > 3600 || now > math.MaxInt64-ttl {
		return Challenge{}, fmt.Errorf("invalid challenge lifetime")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for nonce, c := range g.pending {
		if now >= c.ExpiresAt {
			delete(g.pending, nonce)
		}
	}
	for {
		var random [32]byte
		if _, err := rand.Read(random[:]); err != nil {
			return Challenge{}, err
		}
		c := Challenge{Nonce: hex.EncodeToString(random[:]), ExpiresAt: now + ttl}
		if _, exists := g.pending[c.Nonce]; !exists {
			g.pending[c.Nonce] = c
			return c, nil
		}
	}
}

// Submit reconstructs the public statement using the gateway's enrolled
// authority and task, the issued challenge, and the actual report bytes.
// Submit does not possess the recipient's symmetric key and therefore does not
// authenticate or decrypt the envelope; the recipient must independently call
// OpenReport and reject an invalid authentication tag. A rejected proof,
// expired nonce, or duplicate nullifier consumes neither an
// unexpired challenge nor a fresh nullifier. A successful proof consumes both.
func (g *Gateway) Submit(nonce string, report []byte, nullifier *big.Int, proof groth16.Proof, now int64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	c, exists := g.pending[nonce]
	if !exists {
		return ErrUnknownChallenge
	}
	if now <= 0 || now >= c.ExpiresAt {
		return ErrExpiredChallenge
	}
	if nullifier == nil || nullifier.Sign() < 0 || nullifier.Cmp(fr.Modulus()) >= 0 {
		return fmt.Errorf("invalid nullifier")
	}
	if proof == nil {
		return ErrInvalidProof
	}
	key := nullifier.String()
	if _, exists := g.usedNullifiers[key]; exists {
		return ErrDuplicateReport
	}
	statement, err := PublicStatement(g.authority, g.task, c, report, nullifier)
	if err != nil {
		return fmt.Errorf("invalid public statement: %w", err)
	}
	public, err := frontend.NewWitness(statement, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("invalid public witness: %w", err)
	}
	if err := groth16.Verify(proof, g.vk, public); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidProof, err)
	}
	delete(g.pending, nonce)
	g.usedNullifiers[key] = struct{}{}
	return nil
}
