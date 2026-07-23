package runtime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Pool manages a set of (Module, Instance) pairs for concurrent access to
// a single plugin's functionality. Each pair is single-threaded; the pool
// provides concurrency by handing out different pairs to different goroutines.
type Pool struct {
	plugin   *Plugin
	env      *Env
	moduleID string
	config   string

	idle chan *poolEntry
	cfg  PoolConfig

	// total tracks the number of live instances (idle + in-use).
	total atomic.Int64

	// sem is used to block Get when at max capacity. nil when unlimited.
	sem chan struct{}

	closed atomic.Bool
	mu     sync.Mutex // guards draining on Close
}

type poolEntry struct {
	mod  *Module
	inst *Instance
}

// PoolConfig configures pool sizing.
type PoolConfig struct {
	// MinInstances is the number of instances created at pool initialization.
	// Default: 1.
	MinInstances int
	// MaxInstances caps pool growth. 0 = unlimited (grow on demand, never reject).
	// When the pool is exhausted and max is reached, Get blocks until one is returned.
	MaxInstances int
}

// poolCloseTimeout bounds instance teardown during Put-after-Close.
const poolCloseTimeout = 30 * time.Second

var (
	errPoolClosed = errors.New("caddywit: pool is closed")
)

// NewPool creates a pool. It eagerly creates MinInstances pairs. The plugin
// is compiled once; each pool slot is a fresh Instantiate + Provision.
func NewPool(ctx context.Context, plugin *Plugin, env *Env, moduleID, configJSON string, cfg PoolConfig) (*Pool, error) {
	if cfg.MinInstances <= 0 {
		cfg.MinInstances = 1
	}
	if cfg.MaxInstances > 0 && cfg.MinInstances > cfg.MaxInstances {
		cfg.MinInstances = cfg.MaxInstances
	}

	// Channel buffer sized to max if bounded, otherwise to a reasonable starting size.
	bufSize := cfg.MaxInstances
	if bufSize <= 0 {
		bufSize = cfg.MinInstances * 4
		if bufSize < 16 {
			bufSize = 16
		}
	}

	p := &Pool{
		plugin:   plugin,
		env:      env,
		moduleID: moduleID,
		config:   configJSON,
		idle:     make(chan *poolEntry, bufSize),
		cfg:      cfg,
	}

	if cfg.MaxInstances > 0 {
		p.sem = make(chan struct{}, cfg.MaxInstances)
	}

	// Eagerly create MinInstances.
	for i := 0; i < cfg.MinInstances; i++ {
		entry, err := p.newEntry(ctx)
		if err != nil {
			// Clean up already-created entries.
			p.drainClose(ctx)
			return nil, fmt.Errorf("caddywit: pool init instance %d: %w", i, err)
		}
		p.idle <- entry
		p.total.Add(1)
		if p.sem != nil {
			p.sem <- struct{}{}
		}
	}

	return p, nil
}

// newEntry creates a fresh (Module, Instance) pair.
func (p *Pool) newEntry(ctx context.Context) (*poolEntry, error) {
	// Clone env so each module gets its own pointer (same config, independent state).
	envCopy := *p.env
	mod, err := p.plugin.Instantiate(ctx, &envCopy)
	if err != nil {
		return nil, err
	}
	inst, err := mod.Provision(ctx, p.moduleID, p.config)
	if err != nil {
		_ = mod.Close(ctx)
		return nil, err
	}
	return &poolEntry{mod: mod, inst: inst}, nil
}

// Get retrieves a ready Instance, blocking if the pool is exhausted and at
// max capacity. The returned Instance MUST be returned via Put.
// ctx cancellation unblocks a waiting Get with an error.
func (p *Pool) Get(ctx context.Context) (*Instance, error) {
	if p.closed.Load() {
		return nil, errPoolClosed
	}

	// Fast path: try to grab an idle entry.
	select {
	case entry := <-p.idle:
		return entry.inst, nil
	default:
	}

	// Need to grow or wait.
	if p.sem != nil {
		// Bounded: acquire a slot (blocks if at max).
		select {
		case p.sem <- struct{}{}:
			// Got a slot — but first check if an idle entry appeared.
			select {
			case entry := <-p.idle:
				// Someone returned one while we were acquiring the slot.
				// Release the extra sem slot since the entry already has one.
				<-p.sem
				return entry.inst, nil
			default:
			}
			// Create a new instance.
			entry, err := p.newEntry(ctx)
			if err != nil {
				<-p.sem // release slot
				return nil, err
			}
			p.total.Add(1)
			return entry.inst, nil
		case entry := <-p.idle:
			return entry.inst, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Unbounded: just grow.
	entry, err := p.newEntry(ctx)
	if err != nil {
		return nil, err
	}
	p.total.Add(1)
	return entry.inst, nil
}

// Put returns an Instance to the pool. If the pool is closed, the instance
// is closed instead. Safe to call with nil (no-op).
func (p *Pool) Put(inst *Instance) {
	if inst == nil {
		return
	}

	if p.closed.Load() {
		p.closeEntry(inst)
		return
	}

	entry := &poolEntry{mod: inst.Module(), inst: inst}
	select {
	case p.idle <- entry:
		// Returned to pool.
	default:
		// Channel full (possible after dynamic resizing) — close excess.
		p.closeEntry(inst)
		p.total.Add(-1)
		if p.sem != nil {
			<-p.sem
		}
	}
}

// Close drains the pool, closing all idle instances. In-use instances will
// be closed when Put is called. Safe to call multiple times.
func (p *Pool) Close(ctx context.Context) error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil
	}
	return p.drainClose(ctx)
}

func (p *Pool) drainClose(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var errs []error
	for {
		select {
		case entry := <-p.idle:
			errs = append(errs, p.closeEntryFull(ctx, entry))
			p.total.Add(-1)
			if p.sem != nil {
				<-p.sem
			}
		default:
			return errors.Join(errs...)
		}
	}
}

func (p *Pool) closeEntry(inst *Instance) {
	ctx, cancel := context.WithTimeout(context.Background(), poolCloseTimeout)
	defer cancel()
	_ = inst.Cleanup(ctx)
	_ = inst.Module().Close(ctx)
}

func (p *Pool) closeEntryFull(ctx context.Context, entry *poolEntry) error {
	var errs []error
	if entry.inst != nil {
		errs = append(errs, entry.inst.Cleanup(ctx))
	}
	if entry.mod != nil {
		errs = append(errs, entry.mod.Close(ctx))
	}
	return errors.Join(errs...)
}

// Len reports the current total number of instances (idle + in-use).
func (p *Pool) Len() int {
	return int(p.total.Load())
}
