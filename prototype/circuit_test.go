package eventreport

import (
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func testTask() Task {
	return Task{ID: "task-001", Lower: [3]uint32{10, 20, 100}, Upper: [3]uint32{30, 50, 200}}
}
func testChallenge() Challenge { return Challenge{Nonce: strings.Repeat("12", 32), ExpiresAt: 2000} }

func TestCircuitReportEventBindingAndNegativeControls(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	task, challenge := testTask(), testChallenge()
	report := []byte("sensor report A")
	valid := func() *Circuit {
		t.Helper()
		a, e := f.Assignment(task, challenge, report, [3]uint32{20, 30, 150})
		if e != nil {
			t.Fatal(e)
		}
		return a
	}
	solved := func(a *Circuit) error {
		w, e := frontend.NewWitness(a, ecc.BN254.ScalarField())
		if e != nil {
			return e
		}
		return ccs.IsSolved(w)
	}
	if err := solved(valid()); err != nil {
		t.Fatalf("valid assignment: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Circuit)
	}{
		{"modified coordinates", func(a *Circuit) { a.Event[0] = 21 }},
		{"modified time", func(a *Circuit) { a.Event[2] = 151 }},
		{"modified report context", func(a *Circuit) { a.Context = 1 }},
		{"changed task nullifier", func(a *Circuit) { a.Nullifier = 1 }},
		{"another holder secret", func(a *Circuit) { a.Secret = big.NewInt(12345) }},
		{"invalid receipt", func(a *Circuit) { a.Receipt.S = 0 }},
		{"invalid credential", func(a *Circuit) { a.Credential.S = 0 }},
		{"invalid issuer authorization", func(a *Circuit) { a.IssuerCertificate.S = 0 }},
		{"policy excludes event", func(a *Circuit) { a.PolicyLo[0] = 21 }},
		{"invalid bounds", func(a *Circuit) { a.PolicyLo[0] = 31 }},
		{"out-of-range time", func(a *Circuit) { a.Event[2] = new(big.Int).Lsh(big.NewInt(1), 32) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := valid()
			tc.mutate(a)
			if err := solved(a); err == nil {
				t.Fatal("invalid witness satisfied circuit")
			}
		})
	}

	// Even a CA-certified identity issuer must not authenticate arbitrary
	// receipts through the neutral-point signature equation.
	t.Run("certified neutral issuer", func(t *testing.T) {
		a := valid()
		a.Issuer.A.X = 0
		a.Issuer.A.Y = 1
		issuerID, e := nativeHash(n(domainIssuer), n(0), n(1))
		if e != nil {
			t.Fatal(e)
		}
		a.IssuerCertificate, e = sign(f.Authority, issuerID)
		if e != nil {
			t.Fatal(e)
		}
		a.Receipt.R.X = 0
		a.Receipt.R.Y = 1
		a.Receipt.S = 0
		if e = solved(a); e == nil {
			t.Fatal("certified neutral issuer accepted")
		}
	})

	// A newly issued authentic receipt outside the task bounds must also fail.
	t.Run("authentic outside event", func(t *testing.T) {
		a, e := f.Assignment(task, challenge, report, [3]uint32{9, 30, 150})
		if e != nil {
			t.Fatal(e)
		}
		if e = solved(a); e == nil {
			t.Fatal("outside event accepted")
		}
	})
	t.Run("inclusive boundaries", func(t *testing.T) {
		a, e := f.Assignment(task, challenge, report, [3]uint32{10, 50, 200})
		if e != nil {
			t.Fatal(e)
		}
		if e = solved(a); e != nil {
			t.Fatalf("valid boundary rejected: %v", e)
		}
	})
}

func TestNullifierScopeAndRealGroth16(t *testing.T) {
	f, err := NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	task, challenge := testTask(), testChallenge()
	a, err := f.Assignment(task, challenge, []byte("report A"), [3]uint32{20, 30, 150})
	if err != nil {
		t.Fatal(err)
	}
	otherChallenge := challenge
	otherChallenge.Nonce = strings.Repeat("34", 32)
	b, err := f.Assignment(task, otherChallenge, []byte("report B"), [3]uint32{20, 30, 150})
	if err != nil {
		t.Fatal(err)
	}
	if a.Nullifier.(*big.Int).Cmp(b.Nullifier.(*big.Int)) != 0 {
		t.Fatal("same task nullifier changed")
	}
	otherTask := task
	otherTask.ID = "task-002"
	c, err := f.Assignment(otherTask, challenge, []byte("report A"), [3]uint32{20, 30, 150})
	if err != nil {
		t.Fatal(err)
	}
	if a.Nullifier.(*big.Int).Cmp(c.Nullifier.(*big.Int)) == 0 {
		t.Fatal("cross-task nullifiers equal")
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	witness, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := witness.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err = groth16.Verify(proof, vk, pub); err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}
	statement, err := PublicStatement(f.Authority.Public().Bytes(), task, challenge, []byte("report A"), a.Nullifier.(*big.Int))
	if err != nil {
		t.Fatal(err)
	}
	verifierW, err := frontend.NewWitness(statement, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatal(err)
	}
	if err = groth16.Verify(proof, vk, verifierW); err != nil {
		t.Fatalf("reconstructed statement rejected: %v", err)
	}
	altered, err := PublicStatement(f.Authority.Public().Bytes(), task, challenge, []byte("report B"), a.Nullifier.(*big.Int))
	if err != nil {
		t.Fatal(err)
	}
	alteredW, err := frontend.NewWitness(altered, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatal(err)
	}
	if err = groth16.Verify(proof, vk, alteredW); err == nil {
		t.Fatal("proof accepted for substituted report")
	}
}

// Authorized but invalid issuer points must not enable a receipt forgery.
func TestInvalidCertifiedPointsAndSignatureR(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	solve := func(a *Circuit) error {
		w, e := frontend.NewWitness(a, ecc.BN254.ScalarField())
		if e != nil {
			return e
		}
		return ccs.IsSolved(w)
	}
	for _, tc := range []struct {
		name string
		x, y *big.Int
	}{
		{"order two", big.NewInt(0), new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1))},
		{"off curve", big.NewInt(1), big.NewInt(1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, e := f.Assignment(testTask(), testChallenge(), []byte("r"), [3]uint32{20, 30, 150})
			if e != nil {
				t.Fatal(e)
			}
			a.Issuer.A.X, a.Issuer.A.Y = tc.x, tc.y
			id, e := nativeHash(n(domainIssuer), tc.x, tc.y)
			if e != nil {
				t.Fatal(e)
			}
			a.IssuerCertificate, e = sign(f.Authority, id)
			if e != nil {
				t.Fatal(e)
			}
			a.Receipt.R.X, a.Receipt.R.Y, a.Receipt.S = 0, 1, 0
			if e = solve(a); e == nil {
				t.Fatal("invalid certified point accepted")
			}
		})
	}
	t.Run("off curve signature R", func(t *testing.T) {
		a, e := f.Assignment(testTask(), testChallenge(), []byte("r"), [3]uint32{20, 30, 150})
		if e != nil {
			t.Fatal(e)
		}
		a.Receipt.R.X, a.Receipt.R.Y = 1, 1
		if e = solve(a); e == nil {
			t.Fatal("off-curve signature accepted")
		}
	})
}
