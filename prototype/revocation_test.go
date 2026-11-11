package eventreport

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func TestActiveCredentialGroth16Revocation(t *testing.T) {
	task := Task{ID: "active-credential-test", Lower: [3]uint32{10, 20, 100}, Upper: [3]uint32{30, 50, 200}}
	policy, err := NewRegionPolicy(task, [][2]uint32{{20, 30}, {21, 31}})
	if err != nil {
		t.Fatal(err)
	}
	alice, err := NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	// Two separate credential secrets, one trusted authority and issuer.
	bob.Authority, bob.Issuer = alice.Authority, alice.Issuer
	aliceID, err := ActiveCredentialID(alice.Secret)
	if err != nil {
		t.Fatal(err)
	}
	bobID, err := ActiveCredentialID(bob.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if aliceID.Cmp(bobID) == 0 {
		t.Fatal("unexpected credential digest collision")
	}
	oldPolicy, err := NewActivePolicy([]*big.Int{aliceID, bobID})
	if err != nil {
		t.Fatal(err)
	}
	oldRoot := oldPolicy.Root()
	newPolicy, err := oldPolicy.Remove(aliceID)
	if err != nil {
		t.Fatal(err)
	}
	if oldRoot.Cmp(newPolicy.Root()) == 0 || oldPolicy.Root().Cmp(oldRoot) != 0 {
		t.Fatal("remove failed to create a distinct immutable root")
	}

	challenge, report := testChallenge(), []byte("synthetic active credential report")
	auditorSecret, err := NewAccountabilityScalar()
	if err != nil {
		t.Fatal(err)
	}
	auditor, err := AccountabilityPublicKey(auditorSecret)
	if err != nil {
		t.Fatal(err)
	}
	makeAccountability := func(f *Fixture) (*AccountabilityCircuit, AccountabilityCiphertext) {
		t.Helper()
		region, e := policy.Assignment(f, challenge, report, [3]uint32{20, 30, 150}, 0)
		if e != nil {
			t.Fatal(e)
		}
		idScalar, e := NewAccountabilityScalar()
		if e != nil {
			t.Fatal(e)
		}
		identity, e := AccountabilityPublicKey(idScalar)
		if e != nil {
			t.Fatal(e)
		}
		r, e := NewAccountabilityScalar()
		if e != nil {
			t.Fatal(e)
		}
		a, c, e := NewAccountabilityAssignment(region, f.Authority, identity, auditor, r)
		if e != nil {
			t.Fatal(e)
		}
		return a, c
	}
	aliceAcc, aliceCipher := makeAccountability(alice)
	bobAcc, bobCipher := makeAccountability(bob)
	aliceWitness, err := oldPolicy.Assignment(aliceAcc)
	if err != nil {
		t.Fatal(err)
	}
	bobWitness, err := newPolicy.Assignment(bobAcc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = newPolicy.Assignment(aliceAcc); err == nil {
		t.Fatal("revoked credential received a new membership path")
	}

	accountabilityVerifier, err := NewAccountabilityVerifier(policy, alice.Authority.Public().Bytes(), auditor)
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
	oldVerifier, err := NewActiveVerifier(accountabilityVerifier, oldPolicy, vk)
	if err != nil {
		t.Fatal(err)
	}
	newVerifier, err := NewActiveVerifier(accountabilityVerifier, newPolicy, vk)
	if err != nil {
		t.Fatal(err)
	}
	prove := func(a *ActiveCircuit) (groth16.Proof, error) {
		w, e := frontend.NewWitness(a, ecc.BN254.ScalarField())
		if e != nil {
			return nil, e
		}
		return groth16.Prove(ccs, pk, w)
	}
	aliceProof, err := prove(aliceWitness)
	if err != nil {
		t.Fatalf("initial active proof: %v", err)
	}
	aliceNullifier := aliceAcc.Region.Base.Nullifier.(*big.Int)
	if err = oldVerifier.Verify(aliceProof, challenge, report, aliceNullifier, aliceCipher); err != nil {
		t.Fatalf("original active root rejected valid proof: %v", err)
	}
	// Only the verifier configuration changes. Neither proof nor the report
	// submitter selects the current root through the Verify API.
	if err = newVerifier.Verify(aliceProof, challenge, report, aliceNullifier, aliceCipher); err == nil {
		t.Fatal("old proof verified against current revoked root")
	}
	// Bypass the helper as a malicious prover would: retain the old private
	// path but assert the new root. The regular Groth16 prover must fail.
	forged := *aliceWitness
	forged.ActiveRoot = newPolicy.Root()
	if _, err = prove(&forged); err == nil {
		t.Fatal("revoked participant generated a proof with stale path and current root")
	}

	bobProof, err := prove(bobWitness)
	if err != nil {
		t.Fatalf("remaining active participant could not prove: %v", err)
	}
	bobNullifier := bobAcc.Region.Base.Nullifier.(*big.Int)
	if err = newVerifier.Verify(bobProof, challenge, report, bobNullifier, bobCipher); err != nil {
		t.Fatalf("remaining active participant rejected: %v", err)
	}
	if err = oldVerifier.Verify(bobProof, challenge, report, bobNullifier, bobCipher); err == nil {
		t.Fatal("proof verified against the wrong active root")
	}

	// A valid different participant cannot replace only the accountability
	// witness while keeping Alice's private active path.
	mix := *aliceWitness
	mix.Accountability = *bobAcc
	if _, err = prove(&mix); err == nil {
		t.Fatal("other credential accepted a copied active membership path")
	}
	badDirection := *bobWitness
	badDirection.ActiveDirections[0] = 2
	if _, err = prove(&badDirection); err == nil {
		t.Fatal("nonboolean active-tree direction accepted")
	}
	t.Logf("active constraints=%d; real proofs: old valid, new-root rejection, remaining participant valid", ccs.GetNbConstraints())
}

func TestActivePolicyConfigurationAndSnapshots(t *testing.T) {
	f, err := NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	d, err := ActiveCredentialID(f.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewActivePolicy([]*big.Int{d, d}); err == nil {
		t.Fatal("duplicate digest accepted")
	}
	if _, err = NewActivePolicy([]*big.Int{nil}); err == nil {
		t.Fatal("nil digest accepted as enrolled")
	}
	if _, err = NewActivePolicy(make([]*big.Int, ActiveCapacity+1)); err == nil {
		t.Fatal("oversized registry accepted")
	}
	p, err := NewActivePolicy([]*big.Int{d})
	if err != nil {
		t.Fatal(err)
	}
	root := p.Root()
	originalID := new(big.Int).Set(d)
	d.SetInt64(0)
	root.SetInt64(0)
	if p.Root().Sign() == 0 || p.index(originalID) < 0 {
		t.Fatal("caller mutated active policy snapshot")
	}
	empty, err := p.Remove(originalID)
	if err != nil {
		t.Fatal(err)
	}
	if empty.index(originalID) >= 0 || p.index(originalID) < 0 {
		t.Fatal("removal did not preserve immutable snapshots")
	}
	if _, err = empty.Remove(originalID); err == nil {
		t.Fatal("removing absent credential succeeded")
	}
	if _, err = ActiveCredentialID(big.NewInt(0)); err == nil {
		t.Fatal("zero secret accepted")
	}
}
