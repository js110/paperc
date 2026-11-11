package eventreport

import (
	"bytes"
	"crypto/mlkem"
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func TestActiveGatewayRevocationAndAtomicAcceptance(t *testing.T) {
	task := Task{ID: "active-gateway", Lower: [3]uint32{10, 20, 100}, Upper: [3]uint32{30, 50, 200}}
	region, err := NewRegionPolicy(task, [][2]uint32{{20, 30}, {21, 31}})
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	active, err := NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	active.Authority, active.Issuer = revoked.Authority, revoked.Issuer
	dRevoked, err := ActiveCredentialID(revoked.Secret)
	if err != nil {
		t.Fatal(err)
	}
	dActive, err := ActiveCredentialID(active.Secret)
	if err != nil {
		t.Fatal(err)
	}
	before, err := NewActivePolicy([]*big.Int{dRevoked, dActive})
	if err != nil {
		t.Fatal(err)
	}
	after, err := before.Remove(dRevoked)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	auditSecret, err := NewAccountabilityScalar()
	if err != nil {
		t.Fatal(err)
	}
	auditor, err := AccountabilityPublicKey(auditSecret)
	if err != nil {
		t.Fatal(err)
	}
	identitySecret, err := NewAccountabilityScalar()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := AccountabilityPublicKey(identitySecret)
	if err != nil {
		t.Fatal(err)
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &ActiveCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := NewActiveGateway(revoked.Authority.Public().Bytes(), region, auditor, before, 1, vk, recipient)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := gateway.Issue(1000, 30)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := gateway.Issue(1000, 30)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := gateway.Issue(1000, 30)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("synthetic active report")
	envelope, err := SealReportMLKEM(recipient.EncapsulationKey(), plaintext, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	type submission struct {
		c      Challenge
		n      *big.Int
		cipher AccountabilityCiphertext
		proof  []byte
	}
	assignment := func(f *Fixture, p *ActivePolicy, c Challenge, data []byte) (*ActiveCircuit, AccountabilityCiphertext) {
		t.Helper()
		regionAssignment, e := region.Assignment(f, c, data, [3]uint32{20, 30, 150}, 0)
		if e != nil {
			t.Fatal(e)
		}
		random, e := NewAccountabilityScalar()
		if e != nil {
			t.Fatal(e)
		}
		account, cipher, e := NewAccountabilityAssignment(regionAssignment, f.Authority, identity, auditor, random)
		if e != nil {
			t.Fatal(e)
		}
		activeAssignment, e := p.Assignment(account)
		if e != nil {
			t.Fatal(e)
		}
		return activeAssignment, cipher
	}
	prove := func(f *Fixture, p *ActivePolicy, c Challenge, data []byte) submission {
		t.Helper()
		a, cipher := assignment(f, p, c, data)
		w, e := frontend.NewWitness(a, ecc.BN254.ScalarField())
		if e != nil {
			t.Fatal(e)
		}
		proof, e := groth16.Prove(ccs, pk, w)
		if e != nil {
			t.Fatal(e)
		}
		var b bytes.Buffer
		if _, e = proof.WriteTo(&b); e != nil {
			t.Fatal(e)
		}
		return submission{c, a.Accountability.Region.Base.Nullifier.(*big.Int), cipher, b.Bytes()}
	}
	oldRevoked := prove(revoked, before, ca, envelope)
	oldActive := prove(active, before, cb, envelope)
	if err = gateway.UpdateActivePolicy(after, 2); err != nil {
		t.Fatal(err)
	}
	version, root := gateway.ActiveSnapshot()
	if version != 2 || root.Cmp(after.Root()) != 0 {
		t.Fatal("wrong update snapshot")
	}
	root.SetInt64(0)
	_, unchanged := gateway.ActiveSnapshot()
	if unchanged.Cmp(after.Root()) != 0 {
		t.Fatal("root mutated through snapshot")
	}
	if err = gateway.UpdateActivePolicy(before, 3); err == nil {
		t.Fatal("old root accepted with fresh version")
	}
	if err = gateway.UpdateActivePolicy(after, 1); err == nil {
		t.Fatal("old revision accepted")
	}
	third, err := NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	dThird, err := ActiveCredentialID(third.Secret)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := NewActivePolicy([]*big.Int{dRevoked, dActive, dThird})
	if err != nil {
		t.Fatal(err)
	}
	if err = gateway.UpdateActivePolicy(restored, 4); err == nil {
		t.Fatal("removed credential restored using new root")
	}
	version, unchanged = gateway.ActiveSnapshot()
	if version != 2 || unchanged.Cmp(after.Root()) != 0 {
		t.Fatal("rejected update changed policy")
	}
	for _, s := range []submission{oldRevoked, oldActive} {
		p, r, e := gateway.SubmitAndOpen(s.c.Nonce, envelope, s.n, s.cipher, s.proof, 1001)
		if !errors.Is(e, ErrInvalidProof) || p != nil || r != nil {
			t.Fatalf("old proof passed updated root: %v", e)
		}
	}
	// Even a malicious holder bypassing the helper and replacing only the
	// public root cannot satisfy the new root with their old private path.
	forged, _ := assignment(revoked, before, ca, envelope)
	forged.ActiveRoot = after.Root()
	forgedW, err := frontend.NewWitness(forged, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = groth16.Prove(ccs, pk, forgedW); err == nil {
		t.Fatal("removed holder proved old path for new root")
	}
	if _, err = after.Assignment(&forged.Accountability); err == nil {
		t.Fatal("removed holder obtained active path")
	}
	currentA := prove(active, after, cb, envelope)
	currentB := prove(active, after, cc, envelope)
	badEnvelope := append([]byte(nil), envelope...)
	badEnvelope[len(badEnvelope)-1] ^= 1
	badTag := prove(active, after, cb, badEnvelope)
	p, r, e := gateway.SubmitAndOpen(cb.Nonce, badEnvelope, badTag.n, badTag.cipher, badTag.proof, 1001)
	if e == nil || errors.Is(e, ErrInvalidProof) || p != nil || r != nil {
		t.Fatalf("bad AEAD should fail after proof: %v", e)
	}
	var wg sync.WaitGroup
	type result struct {
		plain  []byte
		record *AcceptedAccountabilityRecord
		err    error
	}
	results := make(chan result, 2)
	for _, s := range []submission{currentA, currentB} {
		wg.Add(1)
		go func(s submission) {
			defer wg.Done()
			p, r, e := gateway.SubmitAndOpen(s.c.Nonce, envelope, s.n, s.cipher, s.proof, 1002)
			results <- result{p, r, e}
		}(s)
	}
	wg.Wait()
	close(results)
	accepted, duplicate := 0, 0
	for got := range results {
		if got.err == nil {
			accepted++
			if !bytes.Equal(got.plain, plaintext) || got.record == nil {
				t.Fatal("accepted wrong data")
			}
			opened, e := got.record.OpenIdentity(auditSecret)
			if e != nil || !opened.Equal(&identity) {
				t.Fatalf("identity opening: %v", e)
			}
		} else if errors.Is(got.err, ErrDuplicateReport) {
			duplicate++
			if got.plain != nil || got.record != nil {
				t.Fatal("duplicate returned data")
			}
		} else {
			t.Fatalf("unexpected result: %v", got.err)
		}
	}
	if accepted != 1 || duplicate != 1 {
		t.Fatalf("accepted=%d duplicate=%d", accepted, duplicate)
	}
}
