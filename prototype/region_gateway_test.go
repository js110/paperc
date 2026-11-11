package eventreport

import (
	"bytes"
	"crypto/mlkem"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func TestRegionGatewayActualProofsAndAtomicAcceptance(t *testing.T) {
	task := Task{ID: "region-gateway-task", Lower: [3]uint32{10, 20, 100}, Upper: [3]uint32{30, 50, 200}}
	policy, err := NewRegionPolicy(task, [][2]uint32{{20, 30}, {21, 31}})
	if err != nil {
		t.Fatal(err)
	}
	// A prover tries this different root to include an unauthorized location.
	otherPolicy, err := NewRegionPolicy(task, [][2]uint32{{22, 32}, {21, 31}})
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &RegionCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	key, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := NewRegionGateway(f.Authority.Public().Bytes(), policy, vk, key)
	if err != nil {
		t.Fatal(err)
	}
	a, err := gateway.Issue(1000, 30)
	if err != nil {
		t.Fatal(err)
	}
	b, err := gateway.Issue(1000, 30)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("synthetic encrypted report")
	envelope, err := SealReportMLKEM(key.EncapsulationKey(), plaintext, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenReportMLKEM(key, envelope, task.ID)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("KEM envelope decryption failed: %v", err)
	}
	prove := func(p *RegionPolicy, challenge Challenge, data []byte, event [3]uint32, index int) (groth16.Proof, *big.Int, error) {
		t.Helper()
		assignment, e := p.Assignment(f, challenge, data, event, index)
		if e != nil {
			return nil, nil, e
		}
		w, e := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		if e != nil {
			return nil, nil, e
		}
		proof, e := groth16.Prove(ccs, pk, w)
		return proof, assignment.Base.Nullifier.(*big.Int), e
	}
	proofA, nullifierA, err := prove(policy, a, envelope, [3]uint32{20, 30, 150}, 0)
	if err != nil {
		t.Fatal(err)
	}
	proofB, nullifierB, err := prove(policy, b, envelope, [3]uint32{21, 31, 150}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if nullifierA.Cmp(nullifierB) != 0 {
		t.Fatal("task-scoped nullifier differs")
	}
	if _, _, e := prove(policy, a, envelope, [3]uint32{22, 32, 150}, 0); e == nil {
		t.Fatal("unauthorized location produced proof under trusted root")
	}
	otherProof, otherNullifier, err := prove(otherPolicy, a, envelope, [3]uint32{22, 32, 150}, 0)
	if err != nil {
		t.Fatalf("setup must produce a valid proof under attacker-chosen root: %v", err)
	}
	if err = gateway.Submit(a.Nonce, envelope, otherNullifier, otherProof, 1001); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("attacker-selected root accepted: %v", err)
	}
	gcmStart := 1 + mlkem.CiphertextSize768
	for name, pos := range map[string]int{"KEM ciphertext": 1, "AEAD nonce": gcmStart + 1, "ciphertext": gcmStart + 13, "AEAD tag": len(envelope) - 1} {
		modified := append([]byte(nil), envelope...)
		modified[pos] ^= 1
		if err = gateway.Submit(a.Nonce, modified, nullifierA, proofA, 1001); !errors.Is(err, ErrInvalidProof) {
			t.Fatalf("%s substitution accepted: %v", name, err)
		}
	}
	if err = gateway.Submit(strings.Repeat("12", 32), envelope, nullifierA, proofA, 1001); !errors.Is(err, ErrUnknownChallenge) {
		t.Fatalf("unknown challenge accepted: %v", err)
	}
	// A genuine valid proof for bytes with an invalid AEAD tag must still fail
	// the recipient's authentication, without consuming challenge/nullifier.
	badTag := append([]byte(nil), envelope...)
	badTag[len(badTag)-1] ^= 1
	badTagProof, badTagNullifier, err := prove(policy, a, badTag, [3]uint32{20, 30, 150}, 0)
	if err != nil {
		t.Fatalf("must construct proof independently of AEAD authentication: %v", err)
	}
	if err = gateway.Submit(a.Nonce, badTag, badTagNullifier, badTagProof, 1001); err == nil || errors.Is(err, ErrInvalidProof) {
		t.Fatalf("expected recipient authentication error after a valid proof: %v", err)
	}
	var wg sync.WaitGroup
	type result struct {
		plaintext []byte
		err       error
	}
	results := make(chan result, 2)
	for _, s := range []struct {
		c Challenge
		p groth16.Proof
		n *big.Int
	}{{a, proofA, nullifierA}, {b, proofB, nullifierB}} {
		wg.Add(1)
		go func(s struct {
			c Challenge
			p groth16.Proof
			n *big.Int
		}) {
			defer wg.Done()
			opened, err := gateway.SubmitAndOpen(s.c.Nonce, envelope, s.n, s.p, 1002)
			results <- result{opened, err}
		}(s)
	}
	wg.Wait()
	close(results)
	accepted, duplicate := 0, 0
	for r := range results {
		if r.err == nil {
			if !bytes.Equal(r.plaintext, plaintext) {
				t.Fatalf("accepted report plaintext mismatch: %q", r.plaintext)
			}
			accepted++
		} else if errors.Is(r.err, ErrDuplicateReport) {
			if r.plaintext != nil {
				t.Fatal("duplicate response disclosed plaintext")
			}
			duplicate++
		} else {
			t.Fatalf("unexpected concurrent submission result: %v", r.err)
		}
	}
	if accepted != 1 || duplicate != 1 {
		t.Fatalf("accepted=%d duplicate=%d", accepted, duplicate)
	}
}
