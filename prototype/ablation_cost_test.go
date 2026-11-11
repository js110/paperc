package eventreport

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"math/big"
	"os"
	"testing"
	"time"
)

// Synthetic same-task control, not an implementation of an external scheme.
func TestBindingCostExperiment(t *testing.T) {
	if os.Getenv("EVENT_BINDING_COST") != "1" {
		t.Skip("set EVENT_BINDING_COST=1")
	}
	f, err := NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	task, challenge := testTask(), testChallenge()
	event := [3]uint32{20, 30, 150}
	original, err := f.Assignment(task, challenge, []byte("controlled synthetic report"), event)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := nativeHash(n(domainReceipt), original.Context.(*big.Int), n(0), n(20), n(30), n(150))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := sign(f.Issuer, msg)
	if err != nil {
		t.Fatal(err)
	}
	bare := *original
	bare.Receipt = receipt
	for _, item := range []struct {
		name       string
		circuit    frontend.Circuit
		assignment frontend.Circuit
	}{{"bound", &Circuit{}, original}, {"bearer", &bearerCircuit{}, (*bearerCircuit)(&bare)}} {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, item.circuit)
		if err != nil {
			t.Fatal(err)
		}
		pk, vk, err := groth16.Setup(cs)
		if err != nil {
			t.Fatal(err)
		}
		w, err := frontend.NewWitness(item.assignment, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		pub, err := w.Public()
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("CIRCUIT %s constraints=%d warmup=1 runs=30\n", item.name, cs.GetNbConstraints())
		for i := 0; i <= 30; i++ {
			start := time.Now()
			p, err := groth16.Prove(cs, pk, w)
			elapsed := time.Since(start)
			if err != nil {
				t.Fatal(err)
			}
			start = time.Now()
			err = groth16.Verify(p, vk, pub)
			ve := time.Since(start)
			if err != nil {
				t.Fatal(err)
			}
			if i > 0 {
				fmt.Printf("SAMPLE %s %d %d %d\n", item.name, i, elapsed.Nanoseconds(), ve.Nanoseconds())
			}
		}
	}
}
