package eventreport

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	nativeMiMC "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/signature"
	cryptoeddsa "github.com/consensys/gnark-crypto/signature/eddsa"
	stdeddsa "github.com/consensys/gnark/std/signature/eddsa"
)

// Task is trusted verifier configuration. Task ID denotes the deduplication
// scope and must not be reused for a different authorized policy.
type Task struct {
	ID    string
	Lower [3]uint32
	Upper [3]uint32
}
type Challenge struct {
	Nonce     string
	ExpiresAt int64
}
type transcript struct {
	Version      string
	Task         Task
	Challenge    Challenge
	ReportSHA256 string
}

func (t Task) Validate() error {
	if len(t.ID) == 0 || len(t.ID) > 256 {
		return fmt.Errorf("invalid task ID")
	}
	for i := range t.Lower {
		if t.Lower[i] > t.Upper[i] {
			return fmt.Errorf("invalid policy bounds")
		}
	}
	return nil
}
func (c Challenge) Validate() error {
	if len(c.Nonce) != 64 || c.ExpiresAt <= 0 {
		return fmt.Errorf("invalid challenge")
	}
	if _, err := hex.DecodeString(c.Nonce); err != nil {
		return fmt.Errorf("invalid nonce")
	}
	return nil
}
func digestToField(data []byte) *big.Int {
	h := sha256.Sum256(data)
	return new(big.Int).Mod(new(big.Int).SetBytes(h[:]), fr.Modulus())
}
func TaskField(task Task) (*big.Int, error) {
	if err := task.Validate(); err != nil {
		return nil, err
	}
	// Domain separation and fixed field encoding prevent cross-purpose reuse.
	return digestToField([]byte("event-report-task-v1\x00" + task.ID)), nil
}
func ContextField(task Task, challenge Challenge, report []byte) (*big.Int, error) {
	if err := task.Validate(); err != nil {
		return nil, err
	}
	if err := challenge.Validate(); err != nil {
		return nil, err
	}
	rh := sha256.Sum256(report)
	b, err := json.Marshal(transcript{"event-report-context-v1", task, challenge, hex.EncodeToString(rh[:])})
	if err != nil {
		return nil, err
	}
	return digestToField(b), nil
}

func nativeHash(fields ...*big.Int) (*big.Int, error) {
	h := nativeMiMC.NewMiMC()
	for _, value := range fields {
		if value == nil || value.Sign() < 0 || value.Cmp(fr.Modulus()) >= 0 {
			return nil, fmt.Errorf("noncanonical field")
		}
		var elem fr.Element
		elem.SetBigInt(value)
		encoded := elem.Bytes()
		if _, err := h.Write(encoded[:]); err != nil {
			return nil, err
		}
	}
	return new(big.Int).SetBytes(h.Sum(nil)), nil
}
func n(v int64) *big.Int { return big.NewInt(v) }
func sign(signer signature.Signer, message *big.Int) (stdeddsa.Signature, error) {
	var sig stdeddsa.Signature
	var elem fr.Element
	elem.SetBigInt(message)
	msg := elem.Bytes()
	raw, err := signer.Sign(msg[:], nativeMiMC.NewMiMC())
	if err != nil {
		return sig, err
	}
	sig.Assign(tedwards.BN254, raw)
	return sig, nil
}

// Authority and Issuer are private to the experiment, not production PKI.
// The registration authority must enforce enrollment and issuer authorization.
type Fixture struct {
	Authority signature.Signer
	Issuer    signature.Signer
	Secret    *big.Int
}

func NewFixture() (*Fixture, error) {
	authority, err := cryptoeddsa.New(tedwards.BN254, rand.Reader)
	if err != nil {
		return nil, err
	}
	issuer, err := cryptoeddsa.New(tedwards.BN254, rand.Reader)
	if err != nil {
		return nil, err
	}
	secret, err := rand.Int(rand.Reader, new(big.Int).Sub(fr.Modulus(), big.NewInt(1)))
	if err != nil {
		return nil, err
	}
	secret.Add(secret, big.NewInt(1))
	return &Fixture{authority, issuer, secret}, nil
}
func (f *Fixture) Assignment(task Task, challenge Challenge, report []byte, event [3]uint32) (*Circuit, error) {
	taskID, err := TaskField(task)
	if err != nil {
		return nil, err
	}
	context, err := ContextField(task, challenge, report)
	if err != nil {
		return nil, err
	}
	a := &Circuit{Secret: f.Secret, TaskID: taskID, Context: context}
	a.Authority.Assign(tedwards.BN254, f.Authority.Public().Bytes())
	a.Issuer.Assign(tedwards.BN254, f.Issuer.Public().Bytes())
	// The public-key witness coordinates are converted to native scalars
	// exactly as used by gnark's native twisted-Edwards verifier.
	issuerXBytes, okX := a.Issuer.A.X.([]byte)
	issuerYBytes, okY := a.Issuer.A.Y.([]byte)
	if !okX || !okY {
		return nil, fmt.Errorf("unexpected issuer key coordinate types %T %T", a.Issuer.A.X, a.Issuer.A.Y)
	}
	issuerX := new(big.Int).SetBytes(issuerXBytes)
	issuerY := new(big.Int).SetBytes(issuerYBytes)
	credential, err := nativeHash(n(domainCredential), f.Secret)
	if err != nil {
		return nil, err
	}
	a.Credential, err = sign(f.Authority, credential)
	if err != nil {
		return nil, err
	}
	issuerID, err := nativeHash(n(domainIssuer), issuerX, issuerY)
	if err != nil {
		return nil, err
	}
	a.IssuerCertificate, err = sign(f.Authority, issuerID)
	if err != nil {
		return nil, err
	}
	holder, err := nativeHash(n(domainHolder), f.Secret, context)
	if err != nil {
		return nil, err
	}
	receipt, err := nativeHash(n(domainReceipt), context, holder, n(int64(event[0])), n(int64(event[1])), n(int64(event[2])))
	if err != nil {
		return nil, err
	}
	a.Receipt, err = sign(f.Issuer, receipt)
	if err != nil {
		return nil, err
	}
	a.Nullifier, err = nativeHash(n(domainNullifier), f.Secret, taskID)
	if err != nil {
		return nil, err
	}
	for i := range event {
		a.Event[i] = event[i]
		a.PolicyLo[i] = task.Lower[i]
		a.PolicyHi[i] = task.Upper[i]
	}
	return a, nil
}

// PublicStatement constructs the verifier's view from trusted configuration,
// current challenge, actual report bytes and the claimed task nullifier.
func PublicStatement(authority []byte, task Task, challenge Challenge, report []byte, nullifier *big.Int) (*Circuit, error) {
	if len(authority) != 32 || nullifier == nil || nullifier.Sign() < 0 || nullifier.Cmp(fr.Modulus()) >= 0 {
		return nil, fmt.Errorf("invalid public input")
	}
	taskID, err := TaskField(task)
	if err != nil {
		return nil, err
	}
	context, err := ContextField(task, challenge, report)
	if err != nil {
		return nil, err
	}
	a := &Circuit{TaskID: taskID, Context: context, Nullifier: nullifier}
	a.Authority.Assign(tedwards.BN254, authority)
	for i := range task.Lower {
		a.PolicyLo[i] = task.Lower[i]
		a.PolicyHi[i] = task.Upper[i]
	}
	return a, nil
}
