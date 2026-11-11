package eventreport

import (
	"bytes"
	"crypto/mlkem"
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	ed "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func TestAccountabilityGatewayEndToEnd(t *testing.T) {
	task := Task{ID: "accountability-gateway", Lower: [3]uint32{10, 20, 100}, Upper: [3]uint32{30, 50, 200}}
	policy, err := NewRegionPolicy(task, [][2]uint32{{20, 30}, {21, 31}})
	if err != nil {
		t.Fatal(err)
	}
	alternatePolicy, err := NewRegionPolicy(task, [][2]uint32{{22, 32}, {21, 31}})
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewFixture()
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
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &AccountabilityCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := NewAccountabilityGateway(f.Authority.Public().Bytes(), policy, auditor, vk, recipient)
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
	plaintext := []byte("synthetic accountability report")
	envelope, err := SealReportMLKEM(recipient.EncapsulationKey(), plaintext, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	type submission struct {
		challenge Challenge
		report    []byte
		n         *big.Int
		cipher    AccountabilityCiphertext
		proof     []byte
	}
	prove := func(p *RegionPolicy, c Challenge, data []byte, event [3]uint32, index int, audit ed.PointAffine) submission {
		t.Helper()
		region, e := p.Assignment(f, c, data, event, index)
		if e != nil {
			t.Fatal(e)
		}
		random, e := NewAccountabilityScalar()
		if e != nil {
			t.Fatal(e)
		}
		assignment, cipher, e := NewAccountabilityAssignment(region, f.Authority, identity, audit, random)
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
		var encoded bytes.Buffer
		if _, e = proof.WriteTo(&encoded); e != nil {
			t.Fatal(e)
		}
		return submission{c, data, region.Base.Nullifier.(*big.Int), cipher, encoded.Bytes()}
	}
	sa := prove(policy, a, envelope, [3]uint32{20, 30, 150}, 0, auditor)
	sb := prove(policy, b, envelope, [3]uint32{21, 31, 150}, 1, auditor)
	if sa.n.Cmp(sb.n) != 0 {
		t.Fatal("same task nullifiers differ")
	}
	rootSubstitution := prove(alternatePolicy, a, envelope, [3]uint32{22, 32, 150}, 0, auditor)
	otherSecret, err := NewAccountabilityScalar()
	if err != nil {
		t.Fatal(err)
	}
	otherAuditor, err := AccountabilityPublicKey(otherSecret)
	if err != nil {
		t.Fatal(err)
	}
	auditorSubstitution := prove(policy, a, envelope, [3]uint32{20, 30, 150}, 0, otherAuditor)
	params := ed.GetEdwardsCurve()
	wrongCipher := sa.cipher
	wrongCipher.S.Add(&sa.cipher.S, &params.Base)
	badEnvelope := append([]byte(nil), envelope...)
	badEnvelope[len(badEnvelope)-1] ^= 1
	badAEAD := prove(policy, a, badEnvelope, [3]uint32{20, 30, 150}, 0, auditor)
	cases := []struct {
		name     string
		s        submission
		expected error
	}{
		{"wrong region", rootSubstitution, ErrInvalidProof},
		{"wrong auditor", auditorSubstitution, ErrInvalidProof},
		{"wrong identity ciphertext", submission{a, envelope, sa.n, wrongCipher, sa.proof}, ErrInvalidProof},
		{"modified report tag", submission{a, badEnvelope, sa.n, sa.cipher, sa.proof}, ErrInvalidProof},
		{"malformed proof", submission{a, envelope, sa.n, sa.cipher, []byte("not a proof")}, ErrInvalidProof},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, r, e := gateway.SubmitAndOpen(tc.s.challenge.Nonce, tc.s.report, tc.s.n, tc.s.cipher, tc.s.proof, 1001)
			if !errors.Is(e, tc.expected) || p != nil || r != nil {
				t.Fatalf("expected rejection, plaintext=%x record=%v err=%v", p, r, e)
			}
		})
	}
	// A genuine proof for tampered bytes still cannot pass AEAD. Neither
	// challenge nor nullifier may be consumed by this failed attempt.
	out, record, e := gateway.SubmitAndOpen(a.Nonce, badEnvelope, badAEAD.n, badAEAD.cipher, badAEAD.proof, 1001)
	if e == nil || errors.Is(e, ErrInvalidProof) || out != nil || record != nil {
		t.Fatalf("expected AEAD failure after valid proof: %v", e)
	}
	var wg sync.WaitGroup
	type result struct {
		plain  []byte
		record *AcceptedAccountabilityRecord
		err    error
	}
	results := make(chan result, 2)
	for _, s := range []submission{sa, sb} {
		wg.Add(1)
		go func(s submission) {
			defer wg.Done()
			p, r, e := gateway.SubmitAndOpen(s.challenge.Nonce, s.report, s.n, s.cipher, s.proof, 1002)
			results <- result{p, r, e}
		}(s)
	}
	wg.Wait()
	close(results)
	accepted, duplicate := 0, 0
	for result := range results {
		if result.err == nil {
			accepted++
			if !bytes.Equal(result.plain, plaintext) || result.record == nil {
				t.Fatal("wrong accepted plaintext or missing record")
			}
			opened, e := result.record.OpenIdentity(auditSecret)
			if e != nil || !opened.Equal(&identity) {
				t.Fatalf("wrong opened identity: %v", e)
			}
			// Evidence returned to callers is detached from the retained
			// accepted object, including proof, witness, and identity cipher.
			exposed := result.record.CiphertextSnapshot()
			exposed.S.Add(&exposed.S, &params.Base)
			proofCopy, witnessCopy := result.record.ProofBytes(), result.record.PublicWitnessBytes()
			proofCopy[0] ^= 1
			witnessCopy[0] ^= 1
			openedAgain, e := result.record.OpenIdentity(auditSecret)
			if e != nil || !openedAgain.Equal(&identity) {
				t.Fatalf("record mutated through returned data: %v", e)
			}
			proof := groth16.NewProof(ecc.BN254)
			if _, e = proof.ReadFrom(bytes.NewReader(result.record.ProofBytes())); e != nil {
				t.Fatal(e)
			}
			public, e := witness.New(ecc.BN254.ScalarField())
			if e != nil {
				t.Fatal(e)
			}
			if _, e = public.ReadFrom(bytes.NewReader(result.record.PublicWitnessBytes())); e != nil {
				t.Fatal(e)
			}
			if e = groth16.Verify(proof, vk, public); e != nil {
				t.Fatalf("archived proof and public statement: %v", e)
			}
		} else if errors.Is(result.err, ErrDuplicateReport) {
			duplicate++
			if result.plain != nil || result.record != nil {
				t.Fatal("duplicate returned data")
			}
		} else {
			t.Fatalf("unexpected submission error: %v", result.err)
		}
	}
	if accepted != 1 || duplicate != 1 {
		t.Fatalf("accepted=%d duplicate=%d", accepted, duplicate)
	}
}
