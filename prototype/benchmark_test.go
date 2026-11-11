package eventreport

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
)

// TestBenchmarkExperiment is opt-in: it performs genuine circuit compilation,
// circuit-specific setup and proof operations. The Setup here is a local
// research setup, not a protocol for a production trusted setup.
func TestBenchmarkExperiment(t *testing.T) {
	value := os.Getenv("EVENT_BENCH_RUNS")
	if value == "" {
		t.Skip("set EVENT_BENCH_RUNS to an integer to run the measurement")
	}
	runs, err := strconv.Atoi(value)
	if err != nil || runs < 1 || runs > 10000 {
		t.Fatal("EVENT_BENCH_RUNS must be an integer in [1,10000]")
	}
	logger.Disable()
	info := func(name string, args ...string) string {
		b, e := exec.Command(name, args...).Output()
		if e != nil {
			return "unavailable"
		}
		return strings.TrimSpace(string(b))
	}
	fmt.Printf("experiment=event-report-groth16-v1\nstarted_utc=%s\n", time.Now().UTC().Format(time.RFC3339Nano))
	fmt.Printf("go=%s os=%s arch=%s logical_cpus=%d gomaxprocs=%d\n", runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.GOMAXPROCS(0))
	fmt.Printf("cpu=%q memory_bytes=%s os_product=%q os_version=%q os_build=%q\n", info("sysctl", "-n", "machdep.cpu.brand_string"), info("sysctl", "-n", "hw.memsize"), info("sw_vers", "-productName"), info("sw_vers", "-productVersion"), info("sw_vers", "-buildVersion"))
	fmt.Printf("modules=%q\n", info("go", "list", "-m", "github.com/consensys/gnark", "github.com/consensys/gnark-crypto"))
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range bi.Deps {
			if dep.Path == "github.com/consensys/gnark" || dep.Path == "github.com/consensys/gnark-crypto" {
				fmt.Printf("dependency=%s version=%s checksum=%s\n", dep.Path, dep.Version, dep.Sum)
			}
		}
	}
	for _, path := range []string{"circuit.go", "native.go", "go.mod", "go.sum", "benchmark_test.go"} {
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatalf("read source %s: %v", path, e)
		}
		fmt.Printf("source_sha256 file=%s digest=%x\n", path, sha256.Sum256(b))
	}
	fmt.Printf("backend=Groth16 curve=BN254 r1cs=true runs=%d warmup=1 setup_count=1 compile_count=1\n", runs)

	started := time.Now()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
	compileNS := time.Since(started).Nanoseconds()
	if err != nil {
		t.Fatal(err)
	}
	started = time.Now()
	pk, vk, err := groth16.Setup(ccs)
	setupNS := time.Since(started).Nanoseconds()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("compile_ns=%d setup_ns=%d constraints=%d public_variables_including_one=%d secret_variables=%d\n", compileNS, setupNS, ccs.GetNbConstraints(), ccs.GetNbPublicVariables(), ccs.GetNbSecretVariables())
	f, err := NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	task := Task{ID: "benchmark-task", Lower: [3]uint32{10, 20, 100}, Upper: [3]uint32{30, 50, 200}}
	fmt.Println("sample,prove_ns,verify_ns,proof_bytes,public_witness_bytes")
	for i := 0; i <= runs; i++ {
		challenge := Challenge{Nonce: fmt.Sprintf("%064x", i+1), ExpiresAt: 2000}
		report := []byte(fmt.Sprintf("synthetic benchmark report %08d", i))
		assignment, e := f.Assignment(task, challenge, report, [3]uint32{20, 30, 150})
		if e != nil {
			t.Fatal(e)
		}
		witness, e := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		if e != nil {
			t.Fatal(e)
		}
		public, e := witness.Public()
		if e != nil {
			t.Fatal(e)
		}
		started = time.Now()
		proof, e := groth16.Prove(ccs, pk, witness)
		proveNS := time.Since(started).Nanoseconds()
		if e != nil {
			t.Fatalf("prove sample %d: %v", i, e)
		}
		started = time.Now()
		e = groth16.Verify(proof, vk, public)
		verifyNS := time.Since(started).Nanoseconds()
		if e != nil {
			t.Fatalf("verify sample %d: %v", i, e)
		}
		var proofBytes, publicBytes bytes.Buffer
		if _, e = proof.WriteTo(&proofBytes); e != nil {
			t.Fatal(e)
		}
		if _, e = public.WriteTo(&publicBytes); e != nil {
			t.Fatal(e)
		}
		if i == 0 {
			fmt.Printf("warmup,%d,%d,%d,%d\n", proveNS, verifyNS, proofBytes.Len(), publicBytes.Len())
		} else {
			fmt.Printf("%d,%d,%d,%d,%d\n", i, proveNS, verifyNS, proofBytes.Len(), publicBytes.Len())
		}
	}
	fmt.Printf("completed_utc=%s\n", time.Now().UTC().Format(time.RFC3339Nano))
}
