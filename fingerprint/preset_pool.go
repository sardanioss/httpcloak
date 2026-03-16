package fingerprint

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
)

// PoolStrategy determines how presets are selected from a pool.
type PoolStrategy int

const (
	// PoolRandom selects a random preset each time.
	PoolRandom PoolStrategy = iota
	// PoolRoundRobin cycles through presets sequentially.
	PoolRoundRobin
)

// PresetPool manages a collection of presets with rotation strategies.
type PresetPool struct {
	name     string
	presets  []*Preset
	strategy PoolStrategy
	index    atomic.Int64 // lock-free round-robin counter
	rng      *rand.Rand
	rngMu    sync.Mutex // protects rng only
}

func cryptoSeed() int64 {
	var b [8]byte
	crand.Read(b[:])
	return int64(binary.LittleEndian.Uint64(b[:]))
}

// NewPresetPool creates a pool from pre-built presets.
// Panics if presets is empty.
func NewPresetPool(name string, strategy PoolStrategy, presets []*Preset) *PresetPool {
	if len(presets) == 0 {
		panic("fingerprint: NewPresetPool requires at least 1 preset")
	}
	return &PresetPool{
		name:     name,
		presets:  presets,
		strategy: strategy,
		rng:      rand.New(rand.NewSource(cryptoSeed())),
	}
}

// NewPresetPoolFromFile loads a pool from a JSON file.
// Auto-registers all pool presets to the custom registry.
func NewPresetPoolFromFile(path string) (*PresetPool, error) {
	pf, err := LoadPresetFromFile(path)
	if err != nil {
		return nil, err
	}
	return buildPool(pf)
}

// NewPresetPoolFromJSON loads a pool from JSON bytes.
// Auto-registers all pool presets to the custom registry.
func NewPresetPoolFromJSON(data []byte) (*PresetPool, error) {
	pf, err := LoadPresetFromJSON(data)
	if err != nil {
		return nil, err
	}
	return buildPool(pf)
}

func buildPool(pf *PresetFile) (*PresetPool, error) {
	if pf.Pool != nil {
		return buildPoolFromPoolSpec(pf.Pool)
	}
	if pf.Preset != nil {
		// Single preset → wrap in pool of 1
		p, err := BuildPreset(pf.Preset)
		if err != nil {
			return nil, err
		}
		if p.Name != "" {
			Register(p.Name, p)
		}
		return NewPresetPool(p.Name, PoolRandom, []*Preset{p}), nil
	}
	return nil, fmt.Errorf("preset file has neither 'preset' nor 'pool' field")
}

func buildPoolFromPoolSpec(spec *PoolSpec) (*PresetPool, error) {
	if len(spec.Presets) == 0 {
		return nil, fmt.Errorf("pool %q has 0 presets", spec.Name)
	}

	strategy := PoolRandom
	switch spec.Strategy {
	case "random", "":
		strategy = PoolRandom
	case "round-robin":
		strategy = PoolRoundRobin
	default:
		return nil, fmt.Errorf("unknown pool strategy: %q", spec.Strategy)
	}

	// Build all presets first — only register after all succeed
	presets := make([]*Preset, 0, len(spec.Presets))
	for i := range spec.Presets {
		p, err := BuildPreset(&spec.Presets[i])
		if err != nil {
			return nil, fmt.Errorf("preset %d (%q): %w", i, spec.Presets[i].Name, err)
		}
		presets = append(presets, p)
	}

	// All built successfully — now register
	for _, p := range presets {
		if p.Name != "" {
			Register(p.Name, p)
		}
	}

	return NewPresetPool(spec.Name, strategy, presets), nil
}

// Pick returns a preset using the pool's configured strategy.
func (p *PresetPool) Pick() *Preset {
	switch p.strategy {
	case PoolRoundRobin:
		return p.Next()
	default:
		return p.Random()
	}
}

// Random returns a random preset from the pool. Thread-safe.
func (p *PresetPool) Random() *Preset {
	if len(p.presets) == 1 {
		return p.presets[0]
	}
	p.rngMu.Lock()
	idx := p.rng.Intn(len(p.presets))
	p.rngMu.Unlock()
	return p.presets[idx]
}

// Next returns the next preset using round-robin. Lock-free, thread-safe.
func (p *PresetPool) Next() *Preset {
	if len(p.presets) == 1 {
		return p.presets[0]
	}
	n := int64(len(p.presets))
	idx := p.index.Add(1) - 1
	return p.presets[((idx%n)+n)%n]
}

// Get returns a preset by index. Panics if index is out of range.
func (p *PresetPool) Get(index int) *Preset {
	return p.presets[index]
}

// Size returns the number of presets in the pool.
func (p *PresetPool) Size() int {
	return len(p.presets)
}

// Name returns the pool name.
func (p *PresetPool) Name() string {
	return p.name
}

// Close unregisters all pool presets from the custom registry.
func (p *PresetPool) Close() {
	for _, preset := range p.presets {
		if preset.Name != "" {
			Unregister(preset.Name)
		}
	}
}
