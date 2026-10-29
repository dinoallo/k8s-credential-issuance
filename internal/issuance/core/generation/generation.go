// Package generation owns the key/trust generation lifecycle used by the
// domain plugins and KMS allowlists.
package generation

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

type State string

const (
	Prepared          State = "Prepared"
	Active            State = "Active"
	Renewing          State = "Renewing"
	Draining          State = "Draining"
	Retired           State = "Retired"
	EmergencyDisabled State = "EmergencyDisabled"
)

var (
	ErrUnavailable       = errors.New("signing-key generation is unavailable")
	ErrInvalidTransition = errors.New("invalid signing-key generation transition")
)

type Metadata struct {
	Generation string `json:"generation"`
	KeyID      string `json:"key_id"`
	Algorithm  string `json:"algorithm"`
	KeyRef     string `json:"key_ref,omitempty"`
	State      State  `json:"state"`
}

type Registry struct {
	mu          sync.RWMutex
	generations map[string]Metadata
}

func NewRegistry(generations []Metadata) (*Registry, error) {
	registry := &Registry{generations: make(map[string]Metadata, len(generations))}
	active := 0
	for _, metadata := range generations {
		if metadata.Generation == "" || metadata.KeyID == "" || metadata.Algorithm == "" || !validState(metadata.State) {
			return nil, fmt.Errorf("incomplete or invalid generation metadata")
		}
		if _, exists := registry.generations[metadata.Generation]; exists {
			return nil, fmt.Errorf("duplicate generation %q", metadata.Generation)
		}
		if metadata.State == Active {
			active++
		}
		registry.generations[metadata.Generation] = metadata
	}
	if len(registry.generations) == 0 || active != 1 {
		return nil, fmt.Errorf("expected exactly one active generation, got %d", active)
	}
	return registry, nil
}

func (r *Registry) Metadata(generation string) (Metadata, bool) {
	if r == nil {
		return Metadata{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	metadata, ok := r.generations[generation]
	return metadata, ok
}

func (r *Registry) Active() (Metadata, error) {
	if r == nil {
		return Metadata{}, fmt.Errorf("generation registry is nil")
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var active []Metadata
	for _, metadata := range r.generations {
		if metadata.State == Active {
			active = append(active, metadata)
		}
	}
	if len(active) != 1 {
		return Metadata{}, fmt.Errorf("expected exactly one active generation, got %d", len(active))
	}
	return active[0], nil
}

func (r *Registry) All(publishableOnly bool) []Metadata {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	values := make([]Metadata, 0, len(r.generations))
	for _, metadata := range r.generations {
		if !publishableOnly || PublishingAllowed(metadata.State) {
			values = append(values, metadata)
		}
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Generation < values[j].Generation })
	return values
}

func (r *Registry) SetState(generation string, state State) error {
	if r == nil {
		return fmt.Errorf("generation registry is nil")
	}
	if !validState(state) {
		return fmt.Errorf("unknown generation state %q", state)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	metadata, ok := r.generations[generation]
	if !ok {
		return fmt.Errorf("unknown generation %q", generation)
	}
	if !allowedTransition(metadata.State, state) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, metadata.State, state)
	}
	if state == Active {
		for other, value := range r.generations {
			if other != generation && value.State == Active {
				return fmt.Errorf("%w: generation %q is already active", ErrInvalidTransition, other)
			}
		}
	}
	metadata.State = state
	r.generations[generation] = metadata
	return nil
}

func (r *Registry) EmergencyDisable(generation string) error {
	return r.SetState(generation, EmergencyDisabled)
}

func SigningAllowed(state State) bool {
	return state == Active || state == Renewing || state == Draining
}

func PublishingAllowed(state State) bool {
	return state == Active || state == Renewing || state == Draining
}

func validState(state State) bool {
	switch state {
	case Prepared, Active, Renewing, Draining, Retired, EmergencyDisabled:
		return true
	default:
		return false
	}
}

func allowedTransition(from, to State) bool {
	if from == to {
		return true
	}
	switch from {
	case Prepared:
		return to == Active || to == EmergencyDisabled
	case Active:
		return to == Renewing || to == Draining || to == EmergencyDisabled
	case Renewing:
		return to == Draining || to == EmergencyDisabled
	case Draining:
		return to == Retired || to == EmergencyDisabled
	default:
		return false
	}
}
