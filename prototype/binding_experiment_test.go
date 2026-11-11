package eventreport

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/math/cmp"
)

// bearerCircuit is a purpose-built comparison, not a representation of the
// original paper or any deployed system. It copies Circuit except that the
// receipt commits to constant 0 instead of the holder-secret commitment.
type bearerCircuit Circuit

func (c *bearerCircuit) Define(api frontend.API) error {
	// A nonzero participant secret is essential, but uniform secret generation
	// and one-credential-per-subject are registration assumptions.
	api.AssertIsDifferent(c.Secret, 0)
	cred, err := hashFields(api, domainCredential, c.Secret)
	if err != nil {
		return err
	}
	if err = verifySignature(api, c.Credential, cred, c.Authority); err != nil {
		return err
	}

	// CA enrollment must reject malformed/identity keys.  The statement also
	// enforces that requirement because a certified neutral point could make
	// the cofactor-cleared EdDSA equation hold without an issuer secret.
	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}
	curve.AssertIsOnCurve(c.Issuer.A)
	api.AssertIsEqual(api.Mul(api.IsZero(c.Issuer.A.X), api.IsZero(api.Sub(c.Issuer.A.Y, 1))), 0)
	// ScalarMul reduces its scalar and invokes a GLV hint, which is not
	// suitable for multiplying by the subgroup order itself.  Evaluate the
	// fixed integer by double-and-add instead, without scalar reduction.
	order := curve.Params().Order
	inGroup := c.Issuer.A
	for i := order.BitLen() - 2; i >= 0; i-- {
		inGroup = curve.Double(inGroup)
		if order.Bit(i) == 1 {
			inGroup = curve.Add(inGroup, c.Issuer.A)
		}
	}
	api.AssertIsEqual(inGroup.X, 0)
	api.AssertIsEqual(inGroup.Y, 1)

	issuerIdentity, err := hashFields(api, domainIssuer, c.Issuer.A.X, c.Issuer.A.Y)
	if err != nil {
		return err
	}
	if err = verifySignature(api, c.IssuerCertificate, issuerIdentity, c.Authority); err != nil {
		return err
	}

	nullifier, err := hashFields(api, domainNullifier, c.Secret, c.TaskID)
	if err != nil {
		return err
	}
	api.AssertIsEqual(c.Nullifier, nullifier)
	// Controlled ablation: the public constant replaces the secret-derived
	// holder value. The signer and verifier use this same receipt format;
	// all other credential, key, nullifier, policy, and context checks remain.
	receipt, err := hashFields(api, domainReceipt, c.Context, 0, c.Event[0], c.Event[1], c.Event[2])
	if err != nil {
		return err
	}
	if err = verifySignature(api, c.Receipt, receipt, c.Issuer); err != nil {
		return err
	}

	bound := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), coordinateBits), big.NewInt(1))
	cmp32 := cmp.NewBoundedComparator(api, bound, false)
	for i := range c.Event {
		api.ToBinary(c.Event[i], coordinateBits)
		api.ToBinary(c.PolicyLo[i], coordinateBits)
		api.ToBinary(c.PolicyHi[i], coordinateBits)
		cmp32.AssertIsLessEq(c.PolicyLo[i], c.PolicyHi[i])
		cmp32.AssertIsLessEq(c.PolicyLo[i], c.Event[i])
		cmp32.AssertIsLessEq(c.Event[i], c.PolicyHi[i])
	}
	return nil
}

func TestReceiptBindingAblation(t *testing.T) {
	const scenario = "same-task-and-challenge; attacker-has-valid-own-credential-and-knows-victim-receipt-context-event-before-consumption"
	victim, err := NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	attacker, err := NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	attacker.Authority, attacker.Issuer = victim.Authority, victim.Issuer
	if victim.Secret.Cmp(attacker.Secret) == 0 {
		t.Fatal("distinct participants unexpectedly share a secret")
	}
	task, challenge := testTask(), testChallenge()
	report := []byte("controlled synthetic report")
	event := [3]uint32{20, 30, 150}
	a, err := victim.Assignment(task, challenge, report, event)
	if err != nil {
		t.Fatal(err)
	}
	b, err := attacker.Assignment(task, challenge, report, event)
	if err != nil {
		t.Fatal(err)
	}
	if a.Nullifier.(*big.Int).Cmp(b.Nullifier.(*big.Int)) == 0 {
		t.Fatal("unexpected nullifier collision")
	}
	strongCS, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
	if err != nil {
		t.Fatal(err)
	}
	weakCS, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &bearerCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	solve := func(v frontend.Circuit, weak bool) error {
		w, e := frontend.NewWitness(v, ecc.BN254.ScalarField())
		if e != nil {
			return e
		}
		if weak {
			return weakCS.IsSolved(w)
		}
		return strongCS.IsSolved(w)
	}
	// Valid bound credentials, issuer certificates, and receipts independently
	// pass for both subjects. The stolen A receipt does not belong to B.
	if err := solve(a, false); err != nil {
		t.Fatalf("bound victim valid: %v", err)
	}
	if err := solve(b, false); err != nil {
		t.Fatalf("bound attacker own receipt: %v", err)
	}
	stolenBound := *b
	stolenBound.Receipt = a.Receipt
	if err := solve(&stolenBound, false); err == nil {
		t.Fatal("bound stolen receipt accepted")
	}

	// The ablation signs the same task, context and event for a bearer receipt.
	// The victim supplies it to A; B is assumed to obtain that same receipt.
	ctx := a.Context.(*big.Int)
	bareMessage, err := nativeHash(n(domainReceipt), ctx, n(0), n(int64(event[0])), n(int64(event[1])), n(int64(event[2])))
	if err != nil {
		t.Fatal(err)
	}
	bareReceipt, err := sign(victim.Issuer, bareMessage)
	if err != nil {
		t.Fatal(err)
	}
	bareA, bareB := *a, *b
	bareA.Receipt, bareB.Receipt = bareReceipt, bareReceipt
	if err := solve((*bearerCircuit)(&bareA), true); err != nil {
		t.Fatalf("bearer victim valid: %v", err)
	}
	if err := solve((*bearerCircuit)(&bareB), true); err != nil {
		t.Fatalf("bearer attacker with stolen receipt: %v", err)
	}

	// Produce and verify an actual Groth16 proof for the bearer transfer;
	// constraint satisfiability for the bound transfer above is rejected.
	pk, vk, err := groth16.Setup(weakCS)
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness((*bearerCircuit)(&bareB), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(weakCS, pk, w)
	if err != nil {
		t.Fatalf("bearer stolen-receipt proof: %v", err)
	}
	public, err := w.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, public); err != nil {
		t.Fatalf("bearer stolen-receipt verification: %v", err)
	}
	fmt.Printf("MODEL %s\n", scenario)
	fmt.Println("RESULT bound victim-valid=accept attacker-own=accept attacker-stolen=reject (R1CS)")
	fmt.Println("RESULT bearer victim-valid=accept attacker-stolen=accept (R1CS+Groth16)")
	fmt.Println("SCOPE synthetic comparison; no claim against the original system; no relay or physical-truth guarantee")
}
