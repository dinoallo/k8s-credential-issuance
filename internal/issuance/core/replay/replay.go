// Package replay provides atomic single-use state for Grants and proofs.
package replay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	ErrAlreadyConsumed = errors.New("replay item has already been consumed")
	ErrInvalidKey      = errors.New("replay item key is empty")
	ErrInvalidExpiry   = errors.New("replay item expiry is not in the future")
)

type Store interface {
	Consume(context.Context, string, time.Time) error
}

type MemoryStore struct {
	mu      sync.Mutex
	entries map[string]time.Time
	now     func() time.Time
}

func NewMemoryStore(now func() time.Time) *MemoryStore {
	if now == nil {
		now = time.Now
	}
	return &MemoryStore{entries: make(map[string]time.Time), now: now}
}

func (s *MemoryStore) Consume(_ context.Context, key string, expiresAt time.Time) error {
	if s == nil {
		return fmt.Errorf("replay store is nil")
	}
	if key == "" {
		return ErrInvalidKey
	}
	now := s.now()
	if expiresAt.IsZero() || !expiresAt.After(now) {
		return ErrInvalidExpiry
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for existingKey, expiry := range s.entries {
		if !expiry.After(now) {
			delete(s.entries, existingKey)
		}
	}
	if expiry, ok := s.entries[key]; ok && expiry.After(now) {
		return ErrAlreadyConsumed
	}
	s.entries[key] = expiresAt
	return nil
}

// FileStore is restart-safe for one process. It is intentionally not a
// cross-process transaction store; HA deployments must inject one.
type FileStore struct {
	mu      sync.Mutex
	path    string
	now     func() time.Time
	entries map[string]time.Time
}

func NewFileStore(path string, now func() time.Time) (*FileStore, error) {
	if path == "" {
		return nil, fmt.Errorf("replay store path is empty")
	}
	if now == nil {
		now = time.Now
	}
	store := &FileStore{path: path, now: now, entries: make(map[string]time.Time)}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	var entries map[string]time.Time
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("decode replay state: %w", err)
	}
	for key, expiry := range entries {
		if key != "" && expiry.After(now()) {
			store.entries[key] = expiry
		}
	}
	return store, nil
}

func (s *FileStore) Consume(_ context.Context, key string, expiresAt time.Time) error {
	if s == nil {
		return fmt.Errorf("replay store is nil")
	}
	if key == "" {
		return ErrInvalidKey
	}
	now := s.now()
	if expiresAt.IsZero() || !expiresAt.After(now) {
		return ErrInvalidExpiry
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for existingKey, expiry := range s.entries {
		if !expiry.After(now) {
			delete(s.entries, existingKey)
		}
	}
	if expiry, ok := s.entries[key]; ok && expiry.After(now) {
		return ErrAlreadyConsumed
	}
	s.entries[key] = expiresAt
	if err := s.persistLocked(); err != nil {
		delete(s.entries, key)
		return fmt.Errorf("persist replay state: %w", err)
	}
	return nil
}

func (s *FileStore) persistLocked() error {
	parent := filepath.Dir(s.path)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(parent, ".replay-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := json.NewEncoder(temporary).Encode(s.entries); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, s.path)
}
