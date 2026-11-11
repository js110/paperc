package eventreport

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/math/cmp"
	"math/big"
	"testing"
)

// Experimental base-circuit candidate. The issuer signs a holder value and event
// without receiving c. This is not the main manuscript's evaluated protocol.
type hiddenContextCandidate Circuit

func (c *hiddenContextCandidate) Define(api frontend.API) error {
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
	holder, err := hashFields(api, domainHolder, c.Secret, c.Context)
	if err != nil {
		return err
	}
	receipt, err := hashFields(api, domainReceipt, 0, holder, c.Event[0], c.Event[1], c.Event[2])
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

func TestHiddenContextCandidate(t *testing.T) {
	f, err := NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	task, q := testTask(), testChallenge()
	report := []byte("synthetic candidate report")
	event := [3]uint32{20, 30, 150}
	a, err := f.Assignment(task, q, report, event)
	if err != nil {
		t.Fatal(err)
	}
	c := a.Context.(*big.Int)
	h, err := nativeHash(n(domainHolder), f.Secret, c)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := nativeHash(n(domainReceipt), n(0), h, n(20), n(30), n(150))
	if err != nil {
		t.Fatal(err)
	}
	// The issuer signs this tuple only: it does not receive c, secret, or report.
	receipt, err := sign(f.Issuer, msg)
	if err != nil {
		t.Fatal(err)
	}
	a.Receipt = receipt
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &hiddenContextCandidate{})
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness((*hiddenContextCandidate)(a), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		t.Fatal(err)
	}
	p, err := groth16.Prove(cs, pk, w)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := w.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err = groth16.Verify(p, vk, pub); err != nil {
		t.Fatal(err)
	}
	wrong, err := f.Assignment(task, q, []byte("other synthetic report"), event)
	if err != nil {
		t.Fatal(err)
	}
	wrong.Receipt = receipt
	bad, err := frontend.NewWitness((*hiddenContextCandidate)(wrong), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if cs.IsSolved(bad) == nil {
		t.Fatal("accepted reused receipt under altered context")
	}
	other, err := NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	other.Authority = f.Authority
	other.Issuer = f.Issuer
	x, err := other.Assignment(task, q, report, event)
	if err != nil {
		t.Fatal(err)
	}
	x.Receipt = receipt
	bad2, err := frontend.NewWitness((*hiddenContextCandidate)(x), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if cs.IsSolved(bad2) == nil {
		t.Fatal("accepted reused receipt under another holder")
	}
	fmt.Printf("RESULT candidate_valid=Groth16_verified substituted_context=R1CS_rejected substituted_holder=R1CS_rejected constraints=%d\n", cs.GetNbConstraints())
	fmt.Println("SCOPE research candidate base circuit; issuer signature input is (constant,holder,event); role separation and privacy assumptions unproven; no network or extended circuit benchmark")
}
