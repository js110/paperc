package eventreport

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func TestRegionGroth16AndAdversarialInputs(t *testing.T) {
	task := Task{ID: "region-task-1", Lower: [3]uint32{10, 20, 100}, Upper: [3]uint32{30, 50, 200}}
	challenge := testChallenge()
	report := []byte("synthetic report")
	cells := [][2]uint32{{20, 30}, {21, 31}, {23, 33}}
	policy, err := NewRegionPolicy(task, cells)
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &RegionCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	witness := func(a *RegionCircuit) frontend.Circuit { return a }
	prove := func(a *RegionCircuit) (groth16.Proof, error) {
		t.Helper()
		w, e := frontend.NewWitness(witness(a), ecc.BN254.ScalarField())
		if e != nil {
			return nil, e
		}
		return groth16.Prove(ccs, pk, w)
	}
	valid, err := policy.Assignment(f, challenge, report, [3]uint32{20, 30, 150}, 0)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := prove(valid)
	if err != nil {
		t.Fatalf("valid region proof: %v", err)
	}
	nullifier := valid.Base.Nullifier.(*big.Int)
	publicStatement, err := policy.PublicStatement(f.Authority.Public().Bytes(), challenge, report, nullifier)
	if err != nil {
		t.Fatal(err)
	}
	public, err := frontend.NewWitness(publicStatement, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatal(err)
	}
	if err = groth16.Verify(proof, vk, public); err != nil {
		t.Fatalf("proof rejected under verifier policy: %v", err)
	}

	// With another path direction, a second legitimate cell also verifies.
	second, err := policy.Assignment(f, challenge, report, [3]uint32{21, 31, 150}, 1)
	if err != nil {
		t.Fatal(err)
	}
	secondProof, err := prove(second)
	if err != nil {
		t.Fatal(err)
	}
	if err = groth16.Verify(secondProof, vk, public); err != nil {
		t.Fatalf("second authorized cell rejected: %v", err)
	}

	t.Run("public root substitution", func(t *testing.T) {
		other, e := NewRegionPolicy(task, [][2]uint32{{20, 30}, {21, 31}, {24, 34}})
		if e != nil {
			t.Fatal(e)
		}
		wrong, e := other.PublicStatement(f.Authority.Public().Bytes(), challenge, report, nullifier)
		if e != nil {
			t.Fatal(e)
		}
		wrongPublic, e := frontend.NewWitness(wrong, ecc.BN254.ScalarField(), frontend.PublicOnly())
		if e != nil {
			t.Fatal(e)
		}
		if e = groth16.Verify(proof, vk, wrongPublic); e == nil {
			t.Fatal("proof verified against a different trusted policy root")
		}
	})

	negative := []struct {
		name string
		edit func(*RegionCircuit)
	}{
		{"forged sibling", func(a *RegionCircuit) { a.Siblings[0] = new(big.Int).Add(a.Siblings[0].(*big.Int), big.NewInt(1)) }},
		{"forged direction", func(a *RegionCircuit) { a.Directions[0] = 1 }},
		{"nonboolean direction", func(a *RegionCircuit) { a.Directions[0] = 2 }},
		{"forged root", func(a *RegionCircuit) { a.RegionRoot = new(big.Int).Add(policy.Root(), big.NewInt(1)) }},
		{"modified signed location", func(a *RegionCircuit) { a.Base.Event[0] = 22 }},
	}
	for _, tc := range negative {
		t.Run(tc.name, func(t *testing.T) {
			a, e := policy.Assignment(f, challenge, report, [3]uint32{20, 30, 150}, 0)
			if e != nil {
				t.Fatal(e)
			}
			tc.edit(a)
			if _, e = prove(a); e == nil {
				t.Fatal("invalid witness unexpectedly produced a proof")
			}
		})
	}

	// The unauthorized location is genuinely signed and inside the rectangle,
	// but the authorized cell's Merkle path must not authenticate that leaf.
	t.Run("signed unauthorized leaf", func(t *testing.T) {
		a, e := policy.Assignment(f, challenge, report, [3]uint32{22, 32, 150}, 0)
		if e != nil {
			t.Fatal(e)
		}
		baseCCS, e := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
		if e != nil {
			t.Fatal(e)
		}
		baseWitness, e := frontend.NewWitness(&a.Base, ecc.BN254.ScalarField())
		if e != nil {
			t.Fatal(e)
		}
		if e = baseCCS.IsSolved(baseWitness); e != nil {
			t.Fatalf("test event must satisfy the original rectangular relation: %v", e)
		}
		if _, e = prove(a); e == nil {
			t.Fatal("a valid signed unauthorized cell satisfied the region circuit")
		}
	})
	t.Logf("region constraints=%d; valid proofs=2; negative witnesses rejected=6; wrong root verification rejected=1", ccs.GetNbConstraints())
}

func TestRegionPolicyConfiguration(t *testing.T) {
	task := Task{ID: "region-configuration", Upper: [3]uint32{255, 255, 100}}
	if _, err := NewRegionPolicy(task, nil); err == nil {
		t.Fatal("empty region accepted")
	}
	if _, err := NewRegionPolicy(task, [][2]uint32{{1, 2}, {1, 2}}); err == nil {
		t.Fatal("duplicate cell accepted")
	}
	if _, err := NewRegionPolicy(task, [][2]uint32{{256, 2}}); err == nil {
		t.Fatal("cell outside rectangular task bounds accepted")
	}
	cells := make([][2]uint32, RegionCapacity+1)
	for i := range cells {
		cells[i] = [2]uint32{uint32(i % 16), uint32(i / 16)}
	}
	if _, err := NewRegionPolicy(task, cells); err == nil {
		t.Fatal("oversized region accepted")
	}
	p, err := NewRegionPolicy(task, cells[:RegionCapacity])
	if err != nil {
		t.Fatalf("256-cell region rejected: %v", err)
	}
	root := p.Root()
	cells[0][0] = 255
	root.SetInt64(0)
	if p.Root().Sign() == 0 || p.cells[0][0] != 0 {
		t.Fatal("caller mutated trusted policy snapshot")
	}
}
