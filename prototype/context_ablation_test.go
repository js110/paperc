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

// Controlled ablation, not an external scheme.
type noContextCircuit Circuit

func (c *noContextCircuit) Define(api frontend.API) error {
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
	holder, err := hashFields(api, domainHolder, c.Secret, 0)
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

func TestContextBindingAblation(t *testing.T) {
	f, err := NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	task, challenge := testTask(), testChallenge()
	report := []byte("original report")
	event := [3]uint32{20, 30, 150}
	original, err := f.Assignment(task, challenge, report, event)
	if err != nil {
		t.Fatal(err)
	}
	holder, err := nativeHash(n(domainHolder), f.Secret, n(0))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := nativeHash(n(domainReceipt), n(0), holder, n(20), n(30), n(150))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := sign(f.Issuer, msg)
	if err != nil {
		t.Fatal(err)
	}
	strong, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
	if err != nil {
		t.Fatal(err)
	}
	weak, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &noContextCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(weak)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		task      Task
		challenge Challenge
		report    []byte
	}{{"original", task, challenge, report}, {"report_substitution", task, challenge, []byte("substituted report")}, {"challenge_substitution", task, Challenge{Nonce: "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd", ExpiresAt: 2000}, report}}
	task2 := task
	task2.ID = "other-task"
	cases = append(cases, struct {
		name      string
		task      Task
		challenge Challenge
		report    []byte
	}{"task_substitution", task2, challenge, report})
	for _, tc := range cases {
		a, err := f.Assignment(tc.task, tc.challenge, tc.report, event)
		if err != nil {
			t.Fatal(err)
		}
		a.Receipt = original.Receipt
		sw, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		se := strong.IsSolved(sw)
		if tc.name == "original" && se != nil {
			t.Fatalf("strong original: %v", se)
		}
		if tc.name != "original" && se == nil {
			t.Fatalf("strong accepted %s", tc.name)
		}
		a.Receipt = receipt
		ww, err := frontend.NewWitness((*noContextCircuit)(a), ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err = weak.IsSolved(ww); err != nil {
			t.Fatalf("weak %s: %v", tc.name, err)
		}
		p, err := groth16.Prove(weak, pk, ww)
		if err != nil {
			t.Fatalf("prove %s: %v", tc.name, err)
		}
		pub, err := ww.Public()
		if err != nil {
			t.Fatal(err)
		}
		if err = groth16.Verify(p, vk, pub); err != nil {
			t.Fatalf("verify %s: %v", tc.name, err)
		}
		result := "reject"
		if tc.name == "original" {
			result = "accept"
		}
		fmt.Printf("RESULT case=%s bound=%s (R1CS) no_context=accept (R1CS+Groth16)\n", tc.name, result)
	}
	fmt.Println("MODEL same-participant receipt reuse; ablation replaces context in holder and signed receipt with zero; attacker has receipt, not issuer key")
}
