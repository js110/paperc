package eventreport

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	ed "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func TestAccountabilityGroth16AndPinnedOpening(t *testing.T) {
	task := Task{ID: "accountability-test", Lower: [3]uint32{10, 20, 100}, Upper: [3]uint32{30, 50, 200}}
	policy, err := NewRegionPolicy(task, [][2]uint32{{20, 30}, {21, 31}})
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	challenge, report := testChallenge(), []byte("synthetic accountability report")
	region, err := policy.Assignment(f, challenge, report, [3]uint32{20, 30, 150}, 0)
	if err != nil {
		t.Fatal(err)
	}
	identityScalar, err := NewAccountabilityScalar()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := AccountabilityPublicKey(identityScalar)
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
	randomness, err := NewAccountabilityScalar()
	if err != nil {
		t.Fatal(err)
	}
	assignment, cipher, err := NewAccountabilityAssignment(region, f.Authority, identity, auditor, randomness)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewAccountabilityVerifier(policy, f.Authority.Public().Bytes(), auditor)
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
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		t.Fatalf("valid proof: %v", err)
	}
	statement, err := verifier.PublicStatement(challenge, report, region.Base.Nullifier.(*big.Int), cipher)
	if err != nil {
		t.Fatal(err)
	}
	public, err := frontend.NewWitness(statement, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatal(err)
	}
	if err = groth16.Verify(proof, vk, public); err != nil {
		t.Fatalf("valid public statement: %v", err)
	}
	opened, err := OpenAccountabilityCiphertext(auditSecret, auditor, cipher)
	if err != nil || !opened.Equal(&identity) {
		t.Fatalf("open expected identity: %v", err)
	}
	otherSecret, err := NewAccountabilityScalar()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = OpenAccountabilityCiphertext(otherSecret, auditor, cipher); err == nil {
		t.Fatal("mismatched opening key accepted")
	}

	// Change the ciphertext to a different valid group element. The statement
	// remains well-formed, but the original proof must no longer verify.
	params := ed.GetEdwardsCurve()
	forged := cipher
	forged.S.Add(&cipher.S, &params.Base)
	altered, err := verifier.PublicStatement(challenge, report, region.Base.Nullifier.(*big.Int), forged)
	if err != nil {
		t.Fatal(err)
	}
	alteredW, err := frontend.NewWitness(altered, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatal(err)
	}
	if err = groth16.Verify(proof, vk, alteredW); err == nil {
		t.Fatal("substituted ciphertext verified")
	}
	otherAuditor, err := AccountabilityPublicKey(otherSecret)
	if err != nil {
		t.Fatal(err)
	}
	alternate, err := NewAccountabilityVerifier(policy, f.Authority.Public().Bytes(), otherAuditor)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := alternate.PublicStatement(challenge, report, region.Base.Nullifier.(*big.Int), cipher)
	if err != nil {
		t.Fatal(err)
	}
	wrongKeyW, err := frontend.NewWitness(wrongKey, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatal(err)
	}
	if err = groth16.Verify(proof, vk, wrongKeyW); err == nil {
		t.Fatal("proof verified for a different pinned auditor")
	}

	solve := func(a *AccountabilityCircuit) error {
		w, e := frontend.NewWitness(a, ecc.BN254.ScalarField())
		if e != nil {
			return e
		}
		return ccs.IsSolved(w)
	}
	// An otherwise well-formed encryption of a different identity cannot use
	// the original link signature on this participant's secret commitment.
	otherIdentity, err := AccountabilityPublicKey(otherSecret)
	if err != nil {
		t.Fatal(err)
	}
	fake, _, err := NewAccountabilityAssignment(region, f.Authority, otherIdentity, auditor, randomness)
	if err != nil {
		t.Fatal(err)
	}
	fake.LinkSignature = assignment.LinkSignature
	if err = solve(fake); err == nil {
		t.Fatal("wrong CA-linked identity accepted")
	}
	// Another fully valid holder cannot use a link certificate issued for
	// the victim's credential secret even when the encrypted identity matches.
	otherHolder, err := NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	otherHolder.Authority, otherHolder.Issuer = f.Authority, f.Issuer
	otherRegion, err := policy.Assignment(otherHolder, challenge, report, [3]uint32{20, 30, 150}, 0)
	if err != nil {
		t.Fatal(err)
	}
	otherAssignment, _, err := NewAccountabilityAssignment(otherRegion, f.Authority, identity, auditor, randomness)
	if err != nil {
		t.Fatal(err)
	}
	otherAssignment.LinkSignature = assignment.LinkSignature
	if err = solve(otherAssignment); err == nil {
		t.Fatal("other credential accepted original identity link")
	}

	// Supply a *validly signed* identity link and mathematically coherent
	// encryption of an order-two point, bypassing native input validation.
	// Rejection must therefore come from the in-circuit subgroup check.
	var lowOrder ed.PointAffine
	lowOrder.Y.SetOne()
	lowOrder.Y.Neg(&lowOrder.Y)
	badIdentity := *assignment
	badIdentity.Identity = accountabilityPoint(lowOrder)
	d, err := nativeHash(n(domainCredential), f.Secret)
	if err != nil {
		t.Fatal(err)
	}
	badMsg, err := nativeHash(n(domainIdentityLink), d, lowOrder.X.BigInt(new(big.Int)), lowOrder.Y.BigInt(new(big.Int)))
	if err != nil {
		t.Fatal(err)
	}
	badIdentity.LinkSignature, err = sign(f.Authority, badMsg)
	if err != nil {
		t.Fatal(err)
	}
	var shared, lowCipher ed.PointAffine
	shared.ScalarMultiplication(&auditor, randomness)
	lowCipher.Add(&lowOrder, &shared)
	badIdentity.CipherS = accountabilityPoint(lowCipher)
	if err = solve(&badIdentity); err == nil {
		t.Fatal("certified low-order identity accepted")
	}

	// A low-order auditor point is also rejected by the constraints, even
	// if the ciphertext equation itself is made coherent for that point.
	badAuditor := *assignment
	badAuditor.Auditor = accountabilityPoint(lowOrder)
	shared.ScalarMultiplication(&lowOrder, randomness)
	lowCipher.Add(&identity, &shared)
	badAuditor.CipherS = accountabilityPoint(lowCipher)
	if err = solve(&badAuditor); err == nil {
		t.Fatal("low-order auditor accepted by circuit")
	}

	cases := []struct {
		name   string
		mutate func(*AccountabilityCircuit)
	}{
		{"zero randomness", func(a *AccountabilityCircuit) { a.Randomness = 0 }},
		{"order randomness", func(a *AccountabilityCircuit) { a.Randomness = new(big.Int).Set(&params.Order) }},
		{"identity neutral", func(a *AccountabilityCircuit) { a.Identity.X = 0; a.Identity.Y = 1 }},
		{"auditor neutral", func(a *AccountabilityCircuit) { a.Auditor.X = 0; a.Auditor.Y = 1 }},
		{"cipher R changed", func(a *AccountabilityCircuit) { a.CipherR = accountabilityPoint(params.Base) }},
		{"link signature changed", func(a *AccountabilityCircuit) { a.LinkSignature.S = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := *assignment
			tc.mutate(&a)
			if err := solve(&a); err == nil {
				t.Fatal("invalid assignment solved")
			}
		})
	}
	t.Logf("constraints=%d; valid Groth16 proof verified; ciphertext and pinned-key substitutions rejected", ccs.GetNbConstraints())
}

func TestAccountabilityRejectsInvalidPointsAndScalars(t *testing.T) {
	params := ed.GetEdwardsCurve()
	var identity, torsion ed.PointAffine
	identity.Y.SetOne()
	torsion.Y.SetOne()
	torsion.Y.Neg(&torsion.Y)
	for name, p := range map[string]ed.PointAffine{"identity": identity, "order-two": torsion, "off-curve": {}} {
		if err := validateAccountabilityPoint(p, false); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	for _, s := range []*big.Int{nil, big.NewInt(-1), big.NewInt(0), new(big.Int).Set(&params.Order)} {
		if _, err := AccountabilityPublicKey(s); err == nil {
			t.Fatalf("invalid scalar accepted: %v", s)
		}
	}
}
