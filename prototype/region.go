package eventreport

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// A RegionCircuit proves membership of the same privately signed Event[x,y]
// used by Circuit in a fixed-depth tree of authorized discrete cells. It also
// retains Circuit's rectangular x/y/time bounds. Regions are finite sets of
// integer coordinate pairs, not a proof of GPS accuracy or polygon geometry.
const (
	RegionDepth      = 8
	RegionCapacity   = 1 << RegionDepth
	domainEmptyCell  = 201
	domainRegionCell = 202
	domainRegionNode = 203
)

type RegionCircuit struct {
	Base       Circuit
	RegionRoot frontend.Variable `gnark:",public"`
	Siblings   [RegionDepth]frontend.Variable
	// A direction of 0 means the current node is left; 1 means right.
	Directions [RegionDepth]frontend.Variable
}

func (c *RegionCircuit) Define(api frontend.API) error {
	if err := c.Base.Define(api); err != nil {
		return err
	}
	current, err := hashFields(api, domainRegionCell, c.Base.Event[0], c.Base.Event[1])
	if err != nil {
		return err
	}
	for i := 0; i < RegionDepth; i++ {
		api.AssertIsBoolean(c.Directions[i])
		left := api.Select(c.Directions[i], c.Siblings[i], current)
		right := api.Select(c.Directions[i], current, c.Siblings[i])
		current, err = hashFields(api, domainRegionNode, left, right)
		if err != nil {
			return err
		}
	}
	api.AssertIsEqual(current, c.RegionRoot)
	return nil
}

// RegionPolicy is an immutable snapshot of verifier-authorized configuration.
// The task ID must be unique to this exact task and region policy. The verifier
// constructs this object from authenticated configuration, never from a report
// submitter; its root must not be read from a prover-provided proof statement.
// NewRegionPolicy is an in-memory policy compiler, not a configuration-signing
// or distributed policy-management protocol.
type RegionPolicy struct {
	task   Task
	cells  [][2]uint32
	levels [][]*big.Int
}

func NewRegionPolicy(task Task, cells [][2]uint32) (*RegionPolicy, error) {
	if err := task.Validate(); err != nil {
		return nil, err
	}
	if len(cells) == 0 || len(cells) > RegionCapacity {
		return nil, fmt.Errorf("region must contain 1 to %d cells", RegionCapacity)
	}
	p := &RegionPolicy{task: task, cells: append([][2]uint32(nil), cells...), levels: make([][]*big.Int, RegionDepth+1)}
	p.levels[0] = make([]*big.Int, RegionCapacity)
	empty, err := nativeHash(n(domainEmptyCell))
	if err != nil {
		return nil, err
	}
	seen := make(map[[2]uint32]struct{}, len(cells))
	for i := 0; i < RegionCapacity; i++ {
		if i >= len(cells) {
			p.levels[0][i] = new(big.Int).Set(empty)
			continue
		}
		cell := cells[i]
		if _, exists := seen[cell]; exists {
			return nil, fmt.Errorf("duplicate region cell")
		}
		seen[cell] = struct{}{}
		if cell[0] < task.Lower[0] || cell[0] > task.Upper[0] || cell[1] < task.Lower[1] || cell[1] > task.Upper[1] {
			return nil, fmt.Errorf("region cell outside the task bounds")
		}
		p.levels[0][i], err = nativeHash(n(domainRegionCell), n(int64(cell[0])), n(int64(cell[1])))
		if err != nil {
			return nil, err
		}
	}
	for level := 0; level < RegionDepth; level++ {
		p.levels[level+1] = make([]*big.Int, len(p.levels[level])/2)
		for i := range p.levels[level+1] {
			p.levels[level+1][i], err = nativeHash(n(domainRegionNode), p.levels[level][2*i], p.levels[level][2*i+1])
			if err != nil {
				return nil, err
			}
		}
	}
	return p, nil
}

// Root returns a copy: the returned integer cannot change the trusted policy.
func (p *RegionPolicy) Root() *big.Int {
	return new(big.Int).Set(p.levels[RegionDepth][0])
}

// Assignment is only a software fixture: the input event is signed using the
// fixture issuer key. A real issuer must independently verify its observation.
// Merkle constraints enforce that event coordinates match the chosen tree path.
func (p *RegionPolicy) Assignment(f *Fixture, challenge Challenge, report []byte, event [3]uint32, cellIndex int) (*RegionCircuit, error) {
	if p == nil || f == nil || cellIndex < 0 || cellIndex >= len(p.cells) {
		return nil, fmt.Errorf("invalid policy, fixture or cell index")
	}
	base, err := f.Assignment(p.task, challenge, report, event)
	if err != nil {
		return nil, err
	}
	out := &RegionCircuit{Base: *base, RegionRoot: p.Root()}
	index := cellIndex
	for i := 0; i < RegionDepth; i++ {
		out.Siblings[i] = new(big.Int).Set(p.levels[i][index^1])
		out.Directions[i] = index & 1
		index >>= 1
	}
	return out, nil
}

// PublicStatement reconstructs all public values, including the root, using
// only verifier-authorized policy, pinned authority, stored challenge, actual
// received bytes, and the claimed nullifier. It does not itself check freshness,
// replay state, key pinning, or a proof; the verifier must perform those checks.
func (p *RegionPolicy) PublicStatement(authority []byte, challenge Challenge, report []byte, nullifier *big.Int) (*RegionCircuit, error) {
	if p == nil {
		return nil, fmt.Errorf("nil region policy")
	}
	base, err := PublicStatement(authority, p.task, challenge, report, nullifier)
	if err != nil {
		return nil, err
	}
	return &RegionCircuit{Base: *base, RegionRoot: p.Root()}, nil
}
