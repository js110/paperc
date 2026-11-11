package eventreport

import (
	"bytes"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	nativetwistededwards "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// These are end-to-end tests: no verifier stub is used, and every accepted
// report is backed by a Groth16 proof and a statement rebuilt by the gateway.
func TestGatewayGroth16BindingReplayAndAtomicDeduplication(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	task := testTask()
	authority := f.Authority.Public().Bytes()
	gateway, err := NewGateway(authority, task, vk)
	if err != nil {
		t.Fatal(err)
	}
	// Enrolled configuration is a snapshot, not a caller-controlled byte slice.
	authority[0] ^= 0xff

	a, err := gateway.Issue(1000, 30)
	if err != nil {
		t.Fatal(err)
	}
	b, err := gateway.Issue(1000, 30)
	if err != nil {
		t.Fatal(err)
	}
	if a.Nonce == b.Nonce || len(a.Nonce) != 64 || a.ExpiresAt != 1030 {
		t.Fatal("incorrect issued challenges")
	}
	key := bytes.Repeat([]byte{0xa5}, 32)
	plaintext := []byte("sensor report A")
	report, err := SealReport(key, plaintext, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenReport(key, report, task.ID)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("decrypt: %v", err)
	}
	alteredReport := append([]byte(nil), report...)
	alteredReport[len(alteredReport)-1] ^= 1
	if _, err := OpenReport(key, alteredReport, task.ID); err == nil {
		t.Fatal("modified envelope authenticated")
	}
	if _, err := OpenReport(key, report, "another-task"); err == nil {
		t.Fatal("wrong task authenticated")
	}
	makeProof := func(c Challenge) (groth16.Proof, *big.Int) {
		t.Helper()
		assignment, e := f.Assignment(task, c, report, [3]uint32{20, 30, 150})
		if e != nil {
			t.Fatal(e)
		}
		w, e := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		if e != nil {
			t.Fatal(e)
		}
		proof, e := groth16.Prove(ccs, pk, w)
		if e != nil {
			t.Fatal(e)
		}
		return proof, assignment.Nullifier.(*big.Int)
	}
	proofA, nullA := makeProof(a)
	proofB, nullB := makeProof(b)
	if nullA.Cmp(nullB) != 0 {
		t.Fatal("identity's task nullifier changed")
	}
	if err := gateway.Submit(strings.Repeat("11", 32), report, nullA, proofA, 1001); !errors.Is(err, ErrUnknownChallenge) {
		t.Fatalf("unknown challenge: %v", err)
	}
	if err := gateway.Submit(a.Nonce, alteredReport, nullA, proofA, 1001); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("report substitution accepted: %v", err)
	}
	if err := gateway.Submit(a.Nonce, report, nullA, nil, 1001); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("nil proof accepted: %v", err)
	}
	if err := gateway.Submit(a.Nonce, report, big.NewInt(-1), proofA, 1001); err == nil {
		t.Fatal("noncanonical nullifier accepted")
	}

	// Both requests are valid individually, but the same task nullifier can be
	// recorded once even under concurrent submissions.
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, submission := range []struct {
		challenge Challenge
		proof     groth16.Proof
		nullifier *big.Int
	}{{a, proofA, nullA}, {b, proofB, nullB}} {
		submission := submission
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- gateway.Submit(submission.challenge.Nonce, report, submission.nullifier, submission.proof, 1002)
		}()
	}
	wg.Wait()
	close(results)
	accepted, duplicate := 0, 0
	for e := range results {
		if e == nil {
			accepted++
		} else if errors.Is(e, ErrDuplicateReport) {
			duplicate++
		} else {
			t.Fatalf("unexpected submit result: %v", e)
		}
	}
	if accepted != 1 || duplicate != 1 {
		t.Fatalf("accepted %d duplicate %d", accepted, duplicate)
	}
	// Exactly one challenge was consumed; the other is retained on duplicate.
	consumed := 0
	for _, item := range []struct {
		challenge Challenge
		proof     groth16.Proof
		nullifier *big.Int
	}{{a, proofA, nullA}, {b, proofB, nullB}} {
		e := gateway.Submit(item.challenge.Nonce, report, item.nullifier, item.proof, 1003)
		if errors.Is(e, ErrUnknownChallenge) {
			consumed++
		} else if !errors.Is(e, ErrDuplicateReport) {
			t.Fatalf("invalid replay outcome: %v", e)
		}
	}
	if consumed != 1 {
		t.Fatalf("consumed challenges %d", consumed)
	}
	expired, err := gateway.Issue(1000, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.Submit(expired.Nonce, report, nullA, proofA, 1003); !errors.Is(err, ErrExpiredChallenge) {
		t.Fatalf("expiry boundary: %v", err)
	}
}

func TestGatewayRejectsMalformedAuthorities(t *testing.T) {
	// Setup here is used only to provide the required trusted verifier key;
	// malformed authority bytes must be rejected before witness construction.
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
	if err != nil {
		t.Fatal(err)
	}
	_, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	var identity nativetwistededwards.PointAffine
	identity.Y.SetOne()
	neutral := identity.Bytes()
	// Order-two point (0, -1): on-curve but outside the prime-order subgroup.
	var torsion nativetwistededwards.PointAffine
	torsion.Y.SetOne()
	torsion.Y.Neg(&torsion.Y)
	lowOrder := torsion.Bytes()
	for _, key := range [][]byte{nil, make([]byte, 32), neutral[:], lowOrder[:], []byte(strings.Repeat("x", 32))} {
		if _, err := NewGateway(key, testTask(), vk); err == nil {
			t.Fatalf("accepted malformed or non-subgroup key %x", key)
		}
	}
	f, err := NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewGateway(f.Authority.Public().Bytes(), testTask(), vk); err != nil {
		t.Fatalf("rejected generated authority: %v", err)
	}
}
