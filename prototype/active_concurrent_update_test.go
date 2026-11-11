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

// Exercise the actual shared lock between active-root update and acceptance.
// The two legal outcomes are acceptance under the old root before an update,
// or rejection of the old-root proof when the update wins. In both cases an
// independently issued second old-root proof must fail after the update.
func TestActiveGatewayConcurrentUpdateAndSubmission(t *testing.T) {
	task := Task{ID: "active-update-race", Lower: [3]uint32{10, 20, 100}, Upper: [3]uint32{30, 50, 200}}
	region, err := NewRegionPolicy(task, [][2]uint32{{20, 30}, {21, 31}})
	if err != nil {
		t.Fatal(err)
	}
	removed, err := NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	remaining, err := NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	remaining.Authority, remaining.Issuer = removed.Authority, removed.Issuer
	d1, err := ActiveCredentialID(removed.Secret)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := ActiveCredentialID(remaining.Secret)
	if err != nil {
		t.Fatal(err)
	}
	old, err := NewActivePolicy([]*big.Int{d1, d2})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := old.Remove(d1)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	auditorSecret, err := NewAccountabilityScalar()
	if err != nil {
		t.Fatal(err)
	}
	auditor, err := AccountabilityPublicKey(auditorSecret)
	if err != nil {
		t.Fatal(err)
	}
	id1Secret, err := NewAccountabilityScalar()
	if err != nil {
		t.Fatal(err)
	}
	id1, err := AccountabilityPublicKey(id1Secret)
	if err != nil {
		t.Fatal(err)
	}
	id2Secret, err := NewAccountabilityScalar()
	if err != nil {
		t.Fatal(err)
	}
	id2, err := AccountabilityPublicKey(id2Secret)
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
	plaintext := []byte("concurrent active root test")
	envelope, err := SealReportMLKEM(recipient.EncapsulationKey(), plaintext, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	type submission struct {
		challenge Challenge
		nullifier *big.Int
		cipher    AccountabilityCiphertext
		proof     []byte
	}
	makeProof := func(f *Fixture, c Challenge, identitySecret *big.Int) submission {
		t.Helper()
		r, e := region.Assignment(f, c, envelope, [3]uint32{20, 30, 150}, 0)
		if e != nil {
			t.Fatal(e)
		}
		id, e := AccountabilityPublicKey(identitySecret)
		if e != nil {
			t.Fatal(e)
		}
		random, e := NewAccountabilityScalar()
		if e != nil {
			t.Fatal(e)
		}
		a, cipher, e := NewAccountabilityAssignment(r, f.Authority, id, auditor, random)
		if e != nil {
			t.Fatal(e)
		}
		aa, e := old.Assignment(a)
		if e != nil {
			t.Fatal(e)
		}
		w, e := frontend.NewWitness(aa, ecc.BN254.ScalarField())
		if e != nil {
			t.Fatal(e)
		}
		proof, e := groth16.Prove(ccs, pk, w)
		if e != nil {
			t.Fatal(e)
		}
		var buf bytes.Buffer
		if _, e = proof.WriteTo(&buf); e != nil {
			t.Fatal(e)
		}
		return submission{c, new(big.Int).Set(r.Base.Nullifier.(*big.Int)), cipher, buf.Bytes()}
	}
	_ = id1
	_ = id2
	// Deterministic ordering cases establish both legal branches; simultaneous
	// cases start both operations at the same barrier and accept either branch.
	modes := []string{"submit-first", "update-first", "simultaneous-1", "simultaneous-2", "simultaneous-3", "simultaneous-4"}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			gateway, e := NewActiveGateway(removed.Authority.Public().Bytes(), region, auditor, old, 1, vk, recipient)
			if e != nil {
				t.Fatal(e)
			}
			c1, e := gateway.Issue(1000, 30)
			if e != nil {
				t.Fatal(e)
			}
			c2, e := gateway.Issue(1000, 30)
			if e != nil {
				t.Fatal(e)
			}
			first := makeProof(removed, c1, id1Secret)
			late := makeProof(remaining, c2, id2Secret)
			start := make(chan struct{})
			submitted := make(chan struct{})
			updatedDone := make(chan struct{})
			type submitResult struct {
				plain  []byte
				record *AcceptedAccountabilityRecord
				err    error
			}
			result := make(chan submitResult, 1)
			updateResult := make(chan error, 1)
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				if mode == "update-first" {
					<-updatedDone
				}
				p, r, e := gateway.SubmitAndOpen(first.challenge.Nonce, envelope, first.nullifier, first.cipher, first.proof, 1001)
				result <- submitResult{p, r, e}
				close(submitted)
			}()
			go func() {
				defer wg.Done()
				<-start
				if mode == "submit-first" {
					<-submitted
				}
				e := gateway.UpdateActivePolicy(updated, 2)
				updateResult <- e
				close(updatedDone)
			}()
			close(start)
			wg.Wait()
			res := <-result
			if e := <-updateResult; e != nil {
				t.Fatalf("update failed: %v", e)
			}
			version, root := gateway.ActiveSnapshot()
			if version != 2 || root.Cmp(updated.Root()) != 0 {
				t.Fatal("update did not take effect")
			}
			if res.err == nil {
				if mode == "update-first" {
					t.Fatal("old proof accepted after ordered update")
				}
				if !bytes.Equal(res.plain, plaintext) || res.record == nil {
					t.Fatal("accepted data incorrect")
				}
			} else {
				if mode == "submit-first" || !errors.Is(res.err, ErrInvalidProof) || res.plain != nil || res.record != nil {
					t.Fatalf("unexpected submit result: %v", res.err)
				}
			}
			// A second participant with a different nullifier did not submit in
			// the race. Its old-root proof must fail against the new snapshot,
			// and this failed attempt must not consume its challenge or tag.
			p, r, e := gateway.SubmitAndOpen(late.challenge.Nonce, envelope, late.nullifier, late.cipher, late.proof, 1002)
			if !errors.Is(e, ErrInvalidProof) || p != nil || r != nil {
				t.Fatalf("old-root proof accepted after update: %v", e)
			}
			base := gateway.account.region.base
			base.mu.Lock()
			_, pendingLate := base.pending[late.challenge.Nonce]
			_, usedLate := base.usedNullifiers[late.nullifier.String()]
			_, pendingFirst := base.pending[first.challenge.Nonce]
			_, usedFirst := base.usedNullifiers[first.nullifier.String()]
			base.mu.Unlock()
			if !pendingLate || usedLate {
				t.Fatal("failed post-update proof consumed fresh state")
			}
			if res.err == nil {
				if pendingFirst || !usedFirst {
					t.Fatal("successful submission not recorded")
				}
			} else if !pendingFirst || usedFirst {
				t.Fatal("failed racing submission consumed fresh state")
			}
			if e = gateway.UpdateActivePolicy(old, 3); e == nil {
				t.Fatal("rollback to old root accepted")
			}
		})
	}
}
