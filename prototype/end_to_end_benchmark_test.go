package eventreport

import (
	"bytes"
	"crypto/mlkem"
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"runtime"
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

// TestEndToEndExperiment measures one sequential, in-process synthetic
// report workflow. It is not an RSU/vehicle experiment or a network latency
// test. Fixture assignment re-signs the participant credential, the issuer
// certificate, the event receipt and the identity link in every iteration;
// a long-lived registration would normally move some of these costs outside
// the per-report path. The sum of component lengths is not a wire protocol.
func TestEndToEndExperiment(t *testing.T) {
	value := os.Getenv("EVENT_END_TO_END_RUNS")
	if value == "" {
		t.Skip("set EVENT_END_TO_END_RUNS to run the experiment")
	}
	runs, err := strconv.Atoi(value)
	if err != nil || runs < 1 || runs > 254 {
		t.Fatal("EVENT_END_TO_END_RUNS must be in [1,254]")
	}
	logger.Disable()
	info := func(name string, args ...string) string {
		b, e := exec.Command(name, args...).Output()
		if e != nil {
			return "unavailable"
		}
		return strings.TrimSpace(string(b))
	}
	fmt.Printf("experiment=event-report-active-inprocess-v1\nstarted_utc=%s\n", time.Now().UTC().Format(time.RFC3339Nano))
	fmt.Printf("go=%s os=%s arch=%s logical_cpus=%d gomaxprocs=%d\n", runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.GOMAXPROCS(0))
	fmt.Printf("cpu=%q memory_bytes=%s os_product=%q os_version=%q os_build=%q\n", info("sysctl", "-n", "machdep.cpu.brand_string"), info("sysctl", "-n", "hw.memsize"), info("sw_vers", "-productName"), info("sw_vers", "-productVersion"), info("sw_vers", "-buildVersion"))
	fmt.Printf("modules=%q\n", info("go", "list", "-m", "github.com/consensys/gnark", "github.com/consensys/gnark-crypto"))
	for _, path := range []string{"circuit.go", "native.go", "region.go", "accountability.go", "revocation.go", "gateway.go", "region_gateway.go", "accountability_gateway.go", "active_gateway.go", "transport.go", "kem_transport.go", "go.mod", "go.sum", "end_to_end_benchmark_test.go"} {
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatalf("read %s: %v", path, e)
		}
		fmt.Printf("source_sha256 file=%s digest=%x\n", path, sha256.Sum256(b))
	}
	fmt.Printf("backend=Groth16 curve=BN254 region_depth=8 region_cells=256 active_depth=8 active_credentials=256 runs=%d warmup=1 setup_count=1 compile_count=1\n", runs)
	fmt.Println("model=single_process_sequential_synthetic; excludes network, physical event observation, initial key enrollment, setup amortization, trusted clock implementation, disk storage, distributed consensus; fixture re-signs credential and issuer certificate per iteration")

	start := time.Now()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &ActiveCircuit{})
	compileNS := time.Since(start).Nanoseconds()
	if err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	pk, vk, err := groth16.Setup(ccs)
	setupNS := time.Since(start).Nanoseconds()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("compile_ns=%d setup_ns=%d constraints=%d\n", compileNS, setupNS, ccs.GetNbConstraints())
	common, err := NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	type participant struct {
		fixture        *Fixture
		identityScalar *big.Int
	}
	people := make([]participant, runs+1)
	ids := make([]*big.Int, 0, ActiveCapacity)
	for i := range people {
		f, e := NewFixture()
		if e != nil {
			t.Fatal(e)
		}
		f.Authority, f.Issuer = common.Authority, common.Issuer
		id, e := ActiveCredentialID(f.Secret)
		if e != nil {
			t.Fatal(e)
		}
		ids = append(ids, id)
		identityScalar, e := NewAccountabilityScalar()
		if e != nil {
			t.Fatal(e)
		}
		people[i] = participant{f, identityScalar}
	}
	for candidate := int64(1); len(ids) < ActiveCapacity; candidate++ {
		v := big.NewInt(candidate)
		duplicate := false
		for _, d := range ids {
			if d.Cmp(v) == 0 {
				duplicate = true
				break
			}
		}
		if !duplicate {
			ids = append(ids, v)
		}
	}
	task := Task{ID: "synthetic-e2e-task", Lower: [3]uint32{10, 20, 100}, Upper: [3]uint32{30, 50, 200}}
	cells := make([][2]uint32, 0, RegionCapacity)
	cellIndex := -1
	for y := uint32(20); y <= 50 && len(cells) < RegionCapacity; y++ {
		for x := uint32(10); x <= 30 && len(cells) < RegionCapacity; x++ {
			if x == 20 && y == 30 {
				cellIndex = len(cells)
			}
			cells = append(cells, [2]uint32{x, y})
		}
	}
	if len(cells) != RegionCapacity || cellIndex < 0 {
		t.Fatal("invalid synthetic region")
	}
	region, err := NewRegionPolicy(task, cells)
	if err != nil {
		t.Fatal(err)
	}
	active, err := NewActivePolicy(ids)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	auditorSecret, err := NewAccountabilityScalar()
	if err != nil {
		t.Fatal(err)
	}
	auditor, err := AccountabilityPublicKey(auditorSecret)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := NewActiveGateway(common.Authority.Public().Bytes(), region, auditor, active, 1, vk, recipient)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("sample,challenge_ns,encrypt_ns,fixture_sign_and_witness_ns,prove_ns,proof_serialize_ns,gateway_verify_decrypt_dedup_ns,total_to_accept_ns,audit_open_ns,plaintext_bytes,envelope_bytes,proof_bytes,nonce_ascii_bytes,nullifier_bytes,identity_cipher_bytes,component_sum_bytes,public_witness_bytes")
	for i, person := range people {
		plain := []byte(fmt.Sprintf("synthetic vehicular observation %08d", i))
		totalStart := time.Now()
		start = time.Now()
		challenge, e := gateway.Issue(1000, 60)
		challengeNS := time.Since(start).Nanoseconds()
		if e != nil {
			t.Fatal(e)
		}
		start = time.Now()
		envelope, e := SealReportMLKEM(recipient.EncapsulationKey(), plain, task.ID)
		encryptNS := time.Since(start).Nanoseconds()
		if e != nil {
			t.Fatal(e)
		}
		start = time.Now()
		regionAssignment, e := region.Assignment(person.fixture, challenge, envelope, [3]uint32{20, 30, 150}, cellIndex)
		if e != nil {
			t.Fatal(e)
		}
		randomness, e := NewAccountabilityScalar()
		if e != nil {
			t.Fatal(e)
		}
		identity, e := AccountabilityPublicKey(person.identityScalar)
		if e != nil {
			t.Fatal(e)
		}
		account, cipher, e := NewAccountabilityAssignment(regionAssignment, person.fixture.Authority, identity, auditor, randomness)
		if e != nil {
			t.Fatal(e)
		}
		assignment, e := active.Assignment(account)
		if e != nil {
			t.Fatal(e)
		}
		witness, e := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		if e != nil {
			t.Fatal(e)
		}
		fixtureNS := time.Since(start).Nanoseconds()
		start = time.Now()
		proof, e := groth16.Prove(ccs, pk, witness)
		proveNS := time.Since(start).Nanoseconds()
		if e != nil {
			t.Fatal(e)
		}
		start = time.Now()
		var proofBuffer bytes.Buffer
		if _, e = proof.WriteTo(&proofBuffer); e != nil {
			t.Fatal(e)
		}
		serializeNS := time.Since(start).Nanoseconds()
		tag, ok := assignment.Accountability.Region.Base.Nullifier.(*big.Int)
		if !ok {
			t.Fatal("unexpected nullifier type")
		}
		start = time.Now()
		opened, record, e := gateway.SubmitAndOpen(challenge.Nonce, envelope, tag, cipher, proofBuffer.Bytes(), 1001)
		gatewayNS := time.Since(start).Nanoseconds()
		if e != nil || !bytes.Equal(opened, plain) || record == nil {
			t.Fatalf("gateway sample %d: %v", i, e)
		}
		totalNS := time.Since(totalStart).Nanoseconds()
		start = time.Now()
		openedIdentity, e := record.OpenIdentity(auditorSecret)
		auditNS := time.Since(start).Nanoseconds()
		if e != nil || !openedIdentity.Equal(&identity) {
			t.Fatalf("auditor sample %d: %v", i, e)
		}
		public, e := witness.Public()
		if e != nil {
			t.Fatal(e)
		}
		var pub bytes.Buffer
		if _, e = public.WriteTo(&pub); e != nil {
			t.Fatal(e)
		}
		// Compressed Edwards identity-ciphertext points are individually 32 bytes;
		// the nullifier is represented as a padded 32-byte scalar for this
		// accounting. The gateway receives nonce as a 64-character hex string.
		rBytes, sBytes := cipher.R.Bytes(), cipher.S.Bytes()
		nullifierEncoding := tag.FillBytes(make([]byte, 32))
		nullifierBytes := len(nullifierEncoding)
		cipherBytes := len(rBytes) + len(sBytes)
		componentSum := len(envelope) + proofBuffer.Len() + len(challenge.Nonce) + nullifierBytes + cipherBytes
		label := strconv.Itoa(i)
		if i == 0 {
			label = "warmup"
		}
		fmt.Printf("%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n", label, challengeNS, encryptNS, fixtureNS, proveNS, serializeNS, gatewayNS, totalNS, auditNS, len(plain), len(envelope), proofBuffer.Len(), len(challenge.Nonce), nullifierBytes, cipherBytes, componentSum, pub.Len())
	}
	fmt.Printf("completed_utc=%s\n", time.Now().UTC().Format(time.RFC3339Nano))
}
