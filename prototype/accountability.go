package eventreport

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"

	ed "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/frontend"
	circuitEd "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/signature/eddsa"
)

const domainIdentityLink = 301

// AccountabilityCircuit is a research extension: it adds verifiable
// encryption of a CA-linked identity point to the existing region relation.
// It does not implement registration, authorized opening policy or revocation.
type AccountabilityCircuit struct {
	Region        RegionCircuit
	Auditor       circuitEd.Point `gnark:",public"`
	CipherR       circuitEd.Point `gnark:",public"`
	CipherS       circuitEd.Point `gnark:",public"`
	Identity      circuitEd.Point
	LinkSignature eddsa.Signature
	Randomness    frontend.Variable
}

// safeAdd and safeDouble enforce nonzero denominators before invoking the
// library's otherwise unchecked division. We do not use the fake-GLV scalar
// multiplication gadget in the new encryption relation. This is not an audit
// of the inherited EdDSA gadgets used by RegionCircuit.
func accountabilityAdd(api frontend.API, curve circuitEd.Curve, x, y circuitEd.Point) circuitEd.Point {
	v := api.Mul(curve.Params().D, x.X, y.Y, y.X, x.Y)
	api.AssertIsDifferent(api.Add(1, v), 0)
	api.AssertIsDifferent(api.Sub(1, v), 0)
	return curve.Add(x, y)
}
func accountabilityDouble(api frontend.API, curve circuitEd.Curve, x circuitEd.Point) circuitEd.Point {
	d := api.Add(api.Mul(x.Y, x.Y), api.Mul(curve.Params().A, x.X, x.X))
	api.AssertIsDifferent(d, 0)
	api.AssertIsDifferent(api.Sub(2, d), 0)
	return curve.Double(x)
}
func accountabilityGroupCheck(api frontend.API, curve circuitEd.Curve, x circuitEd.Point) {
	curve.AssertIsOnCurve(x)
	api.AssertIsEqual(api.Mul(api.IsZero(x.X), api.IsZero(api.Sub(x.Y, 1))), 0)
	// Fixed-order double and add does not reduce q modulo q or invoke GLV.
	q := curve.Params().Order
	acc := x
	for i := q.BitLen() - 2; i >= 0; i-- {
		acc = accountabilityDouble(api, curve, acc)
		if q.Bit(i) == 1 {
			acc = accountabilityAdd(api, curve, acc, x)
		}
	}
	api.AssertIsEqual(acc.X, 0)
	api.AssertIsEqual(acc.Y, 1)
}
func accountabilityMultiply(api frontend.API, curve circuitEd.Curve, p circuitEd.Point, bits []frontend.Variable) circuitEd.Point {
	acc := circuitEd.Point{X: 0, Y: 1}
	for i := len(bits) - 1; i >= 0; i-- {
		acc = accountabilityDouble(api, curve, acc)
		sum := accountabilityAdd(api, curve, acc, p)
		acc = circuitEd.Point{X: api.Select(bits[i], sum.X, acc.X), Y: api.Select(bits[i], sum.Y, acc.Y)}
	}
	return acc
}
func (c *AccountabilityCircuit) Define(api frontend.API) error {
	if err := c.Region.Define(api); err != nil {
		return err
	}
	curve, err := circuitEd.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}
	accountabilityGroupCheck(api, curve, c.Identity)
	accountabilityGroupCheck(api, curve, c.Auditor)
	// All points are field elements; reconstructed points must be on curve.
	curve.AssertIsOnCurve(c.CipherR)
	curve.AssertIsOnCurve(c.CipherS)
	api.AssertIsDifferent(c.Randomness, 0)
	api.AssertIsLessOrEqual(c.Randomness, new(big.Int).Sub(curve.Params().Order, big.NewInt(1)))
	bits := api.ToBinary(c.Randomness, curve.Params().Order.BitLen())
	base := circuitEd.Point{X: curve.Params().Base[0], Y: curve.Params().Base[1]}
	rG := accountabilityMultiply(api, curve, base, bits)
	rP := accountabilityMultiply(api, curve, c.Auditor, bits)
	sum := accountabilityAdd(api, curve, c.Identity, rP)
	api.AssertIsEqual(c.CipherR.X, rG.X)
	api.AssertIsEqual(c.CipherR.Y, rG.Y)
	api.AssertIsEqual(c.CipherS.X, sum.X)
	api.AssertIsEqual(c.CipherS.Y, sum.Y)
	d, err := hashFields(api, domainCredential, c.Region.Base.Secret)
	if err != nil {
		return err
	}
	msg, err := hashFields(api, domainIdentityLink, d, c.Identity.X, c.Identity.Y)
	if err != nil {
		return err
	}
	return verifySignature(api, c.LinkSignature, msg, c.Region.Base.Authority)
}

// AccountabilityCiphertext is a pair of prime-order curve points. Its second
// point may legitimately be the identity; the first must be non-identity.
type AccountabilityCiphertext struct{ R, S ed.PointAffine }

func validateAccountabilityPoint(p ed.PointAffine, allowIdentity bool) error {
	if !p.IsOnCurve() || (!allowIdentity && p.IsZero()) {
		return fmt.Errorf("invalid point")
	}
	params := ed.GetEdwardsCurve()
	var check ed.PointAffine
	check.ScalarMultiplication(&p, &params.Order)
	if !check.IsZero() {
		return fmt.Errorf("point is not in prime-order subgroup")
	}
	return nil
}
func checkAccountabilityScalar(v *big.Int) error {
	params := ed.GetEdwardsCurve()
	if v == nil || v.Sign() <= 0 || v.Cmp(&params.Order) >= 0 {
		return fmt.Errorf("invalid scalar")
	}
	return nil
}
func accountabilityPoint(p ed.PointAffine) circuitEd.Point {
	return circuitEd.Point{X: p.X.BigInt(new(big.Int)), Y: p.Y.BigInt(new(big.Int))}
}

// NewAccountabilityScalar samples uniformly from [1,q-1].
func NewAccountabilityScalar() (*big.Int, error) {
	params := ed.GetEdwardsCurve()
	max := new(big.Int).Sub(&params.Order, big.NewInt(1))
	out, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	return out.Add(out, big.NewInt(1)), nil
}

// AccountabilityPublicKey returns a curve point for a canonical nonzero scalar.
func AccountabilityPublicKey(secret *big.Int) (ed.PointAffine, error) {
	if err := checkAccountabilityScalar(secret); err != nil {
		return ed.PointAffine{}, err
	}
	params := ed.GetEdwardsCurve()
	var out ed.PointAffine
	out.ScalarMultiplication(&params.Base, secret)
	return out, nil
}

// NewAccountabilityAssignment signs the link with the provided fixture CA.
// It simulates a trusted registrar; it does not validate a real identity.
func NewAccountabilityAssignment(region *RegionCircuit, authority signature.Signer, identity, auditor ed.PointAffine, randomness *big.Int) (*AccountabilityCircuit, AccountabilityCiphertext, error) {
	var zero AccountabilityCiphertext
	if region == nil || authority == nil {
		return nil, zero, fmt.Errorf("missing fixture")
	}
	if err := validateAccountabilityPoint(identity, false); err != nil {
		return nil, zero, fmt.Errorf("identity: %w", err)
	}
	if err := validateAccountabilityPoint(auditor, false); err != nil {
		return nil, zero, fmt.Errorf("auditor: %w", err)
	}
	if err := checkAccountabilityScalar(randomness); err != nil {
		return nil, zero, err
	}
	secret, ok := region.Base.Secret.(*big.Int)
	if !ok {
		return nil, zero, fmt.Errorf("expected native secret")
	}
	d, err := nativeHash(n(domainCredential), secret)
	if err != nil {
		return nil, zero, err
	}
	msg, err := nativeHash(n(domainIdentityLink), d, identity.X.BigInt(new(big.Int)), identity.Y.BigInt(new(big.Int)))
	if err != nil {
		return nil, zero, err
	}
	sig, err := sign(authority, msg)
	if err != nil {
		return nil, zero, err
	}
	params := ed.GetEdwardsCurve()
	var cipher AccountabilityCiphertext
	var shared ed.PointAffine
	cipher.R.ScalarMultiplication(&params.Base, randomness)
	shared.ScalarMultiplication(&auditor, randomness)
	cipher.S.Add(&identity, &shared)
	assignment := &AccountabilityCircuit{Region: *region, Auditor: accountabilityPoint(auditor), CipherR: accountabilityPoint(cipher.R), CipherS: accountabilityPoint(cipher.S), Identity: accountabilityPoint(identity), LinkSignature: sig, Randomness: new(big.Int).Set(randomness)}
	return assignment, cipher, nil
}

// AccountabilityVerifier pins enrolled CA, region policy and auditor key. The
// caller must authenticate configuration and separately enforce challenge and
// replay state as in Gateway; this type only reconstructs proof public inputs.
type AccountabilityVerifier struct {
	policy    *RegionPolicy
	authority []byte
	auditor   ed.PointAffine
}

func NewAccountabilityVerifier(policy *RegionPolicy, authority []byte, auditor ed.PointAffine) (*AccountabilityVerifier, error) {
	if policy == nil || len(authority) != 32 {
		return nil, fmt.Errorf("invalid trusted configuration")
	}
	var a ed.PointAffine
	if _, err := a.SetBytes(authority); err != nil {
		return nil, err
	}
	encoding := a.Bytes()
	if !bytes.Equal(authority, encoding[:]) {
		return nil, fmt.Errorf("noncanonical authority")
	}
	if err := validateAccountabilityPoint(a, false); err != nil {
		return nil, fmt.Errorf("authority: %w", err)
	}
	if err := validateAccountabilityPoint(auditor, false); err != nil {
		return nil, fmt.Errorf("auditor: %w", err)
	}
	return &AccountabilityVerifier{policy: policy, authority: append([]byte(nil), authority...), auditor: auditor}, nil
}
func (v *AccountabilityVerifier) PublicStatement(challenge Challenge, report []byte, nullifier *big.Int, cipher AccountabilityCiphertext) (*AccountabilityCircuit, error) {
	if v == nil || v.policy == nil {
		return nil, fmt.Errorf("missing verifier")
	}
	if err := validateAccountabilityPoint(cipher.R, false); err != nil {
		return nil, fmt.Errorf("cipher R: %w", err)
	}
	if err := validateAccountabilityPoint(cipher.S, true); err != nil {
		return nil, fmt.Errorf("cipher S: %w", err)
	}
	region, err := v.policy.PublicStatement(v.authority, challenge, report, nullifier)
	if err != nil {
		return nil, err
	}
	return &AccountabilityCircuit{Region: *region, Auditor: accountabilityPoint(v.auditor), CipherR: accountabilityPoint(cipher.R), CipherS: accountabilityPoint(cipher.S)}, nil
}

// OpenAccountabilityCiphertext should be called only after independently
// validating a proof against the pinned key and authorizing the opening.
func OpenAccountabilityCiphertext(secret *big.Int, auditor ed.PointAffine, cipher AccountabilityCiphertext) (ed.PointAffine, error) {
	key, err := AccountabilityPublicKey(secret)
	if err != nil {
		return ed.PointAffine{}, err
	}
	if !key.Equal(&auditor) {
		return ed.PointAffine{}, fmt.Errorf("opening key does not match pinned public key")
	}
	if err = validateAccountabilityPoint(cipher.R, false); err != nil {
		return ed.PointAffine{}, err
	}
	if err = validateAccountabilityPoint(cipher.S, true); err != nil {
		return ed.PointAffine{}, err
	}
	var shared, neg, out ed.PointAffine
	shared.ScalarMultiplication(&cipher.R, secret)
	neg.Neg(&shared)
	out.Add(&cipher.S, &neg)
	if err = validateAccountabilityPoint(out, false); err != nil {
		return ed.PointAffine{}, err
	}
	return out, nil
}
