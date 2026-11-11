package eventreport

import (
	"fmt"
	"math/big"
	"testing"
)

// The issuer and verifier receive the same public context. This synthetic test
// demonstrates the linkability of shared context; it is not a privacy fix.
func TestIssuerGatewayContextLinkage(t *testing.T) {
	f, err := NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	task, challenge := testTask(), testChallenge()
	reports := [][]byte{[]byte("synthetic report alpha"), []byte("synthetic report beta")}
	issuerEvents := [][3]uint32{{20, 30, 150}, {21, 31, 151}}
	issuerRecords := map[string][3]uint32{}
	for i, r := range reports {
		c, err := ContextField(task, challenge, r)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := issuerRecords[c.String()]; ok {
			t.Fatal("unexpected test fixture collision")
		}
		issuerRecords[c.String()] = issuerEvents[i]
	}
	for i, r := range reports {
		st, err := PublicStatement(f.Authority.Public().Bytes(), task, challenge, r, big.NewInt(int64(i+1)))
		if err != nil {
			t.Fatal(err)
		}
		c, ok := st.Context.(*big.Int)
		if !ok {
			t.Fatal("unexpected context type")
		}
		if event, ok := issuerRecords[c.String()]; !ok || event != issuerEvents[i] {
			t.Fatalf("context join failed for sample %d", i)
		}
	}
	fmt.Println("RESULT synthetic_issuer_gateway_shared_context_join=2/2")
	fmt.Println("SCOPE synthetic software demonstration of linkability when records are shared; no deployed issuer or network")
}
