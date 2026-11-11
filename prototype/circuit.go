// Package eventreport implements an experimental proof relation for
// anonymous, task-scoped, report-bound spacetime attestations.
package eventreport

import (
	"math/big"

	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/signature/eddsa"
)

const (
	domainCredential = 101
	domainIssuer     = 102
	domainHolder     = 103
	domainReceipt    = 104
	domainNullifier  = 105
	coordinateBits   = 32
)

// Circuit is intentionally limited to a three-dimensional integer task box
// (x,y,time), one anonymous participant credential, and one certified issuer.
// It says nothing about the physical accuracy of the issuer's observations.
type Circuit struct {
	Authority eddsa.PublicKey      `gnark:",public"`
	TaskID    frontend.Variable    `gnark:",public"`
	Context   frontend.Variable    `gnark:",public"`
	Nullifier frontend.Variable    `gnark:",public"`
	PolicyLo  [3]frontend.Variable `gnark:",public"`
	PolicyHi  [3]frontend.Variable `gnark:",public"`

	Secret            frontend.Variable
	Credential        eddsa.Signature
	Issuer            eddsa.PublicKey
	IssuerCertificate eddsa.Signature
	Receipt           eddsa.Signature
	Event             [3]frontend.Variable
}

func hashFields(api frontend.API, fields ...frontend.Variable) (frontend.Variable, error) {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return nil, err
	}
	h.Write(fields...)
	return h.Sum(), nil
}

func verifySignature(api frontend.API, sig eddsa.Signature, msg frontend.Variable, pub eddsa.PublicKey) error {
	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}
	curve.AssertIsOnCurve(pub.A)
	curve.AssertIsOnCurve(sig.R)
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	return eddsa.Verify(curve, sig, msg, pub, &h)
}

func (c *Circuit) Define(api frontend.API) error {
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
	receipt, err := hashFields(api, domainReceipt, c.Context, holder, c.Event[0], c.Event[1], c.Event[2])
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
