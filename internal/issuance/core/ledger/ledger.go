// Package ledger provides the single-use reservation and exact-result
// recovery boundary shared by signer instances.
package ledger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	v1 "github.com/dinoallo/k8s-credential-issuance/api/grant/v1"
)

type State string

const (
	Issued           State = "issued"
	Reserved         State = "reserved"
	Signing          State = "signing"
	Completed        State = "completed"
	RetryableFailure State = "retryable_failure"
	PermanentFailure State = "permanent_failure"
	Revoked          State = "revoked"
)

var (
	ErrConflict         = errors.New("ledger reservation conflicts with an existing request")
	ErrGrantConsumed    = errors.New("Grant has already been reserved by another operation")
	ErrRevoked          = errors.New("Grant is revoked")
	ErrUnknownOperation = errors.New("ledger operation is unknown")
	ErrInProgress       = errors.New("ledger operation is already in progress")
)

type ReservationKey struct {
	GrantID       string    `json:"grant_id"`
	Domain        v1.Domain `json:"domain"`
	RequestID     string    `json:"request_id"`
	RequestDigest string    `json:"request_digest"`
	IdentityRef   string    `json:"identity_ref"`
	TargetUID     string    `json:"target_uid,omitempty"`
	OperationID   string    `json:"operation_id"`
}

type Result struct {
	Artifact   []byte `json:"artifact"`
	Response   []byte `json:"response"`
	KeyID      string `json:"key_id"`
	Generation string `json:"generation"`
	Algorithm  string `json:"algorithm"`
}

type Reservation struct {
	Key     ReservationKey `json:"key"`
	State   State          `json:"state"`
	Result  Result         `json:"result"`
	Failure string         `json:"failure,omitempty"`
	Owned   bool           `json:"-"`
}

type Store interface {
	Reserve(context.Context, ReservationKey) (Reservation, error)
	MarkSigning(context.Context, string) error
	Complete(context.Context, string, Result) error
	Fail(context.Context, string, State, error) error
	Lookup(context.Context, string) (Reservation, bool, error)
	Revoke(context.Context, string) error
	IsRevoked(context.Context, string) (bool, error)
}

type state struct {
	Reservations map[string]Reservation `json:"reservations"`
	Claims       map[string]bool        `json:"-"`
}

func newState() state {
	return state{Reservations: make(map[string]Reservation), Claims: make(map[string]bool)}
}

type MemoryStore struct {
	mu    sync.Mutex
	state state
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{state: newState()}
}

func (s *MemoryStore) Reserve(_ context.Context, key ReservationKey) (Reservation, error) {
	if s == nil {
		return Reservation{}, fmt.Errorf("ledger is nil")
	}
	if err := validateKey(key); err != nil {
		return Reservation{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return reserveLocked(&s.state, key)
}

func (s *MemoryStore) MarkSigning(_ context.Context, operationID string) error {
	if s == nil {
		return fmt.Errorf("ledger is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return markSigningLocked(&s.state, operationID)
}

func (s *MemoryStore) Complete(_ context.Context, operationID string, result Result) error {
	if s == nil {
		return fmt.Errorf("ledger is nil")
	}
	if len(result.Artifact) == 0 || len(result.Response) == 0 {
		return fmt.Errorf("completed ledger result is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return completeLocked(&s.state, operationID, result)
}

func (s *MemoryStore) Fail(_ context.Context, operationID string, failureState State, failure error) error {
	if s == nil {
		return fmt.Errorf("ledger is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return failLocked(&s.state, operationID, failureState, failure)
}

func (s *MemoryStore) Lookup(_ context.Context, operationID string) (Reservation, bool, error) {
	if s == nil {
		return Reservation{}, false, fmt.Errorf("ledger is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	reservation, ok := s.state.Reservations[operationID]
	return cloneReservation(reservation), ok, nil
}

func (s *MemoryStore) Revoke(_ context.Context, grantID string) error {
	if s == nil {
		return fmt.Errorf("ledger is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return revokeLocked(&s.state, grantID)
}

func (s *MemoryStore) IsRevoked(_ context.Context, grantID string) (bool, error) {
	if s == nil {
		return false, fmt.Errorf("ledger is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, reservation := range s.state.Reservations {
		if reservation.Key.GrantID == grantID && reservation.State == Revoked {
			return true, nil
		}
	}
	return false, nil
}

// FileStore is restart-safe for one process. It intentionally does not claim
// to provide cross-process atomicity; HA deployments must replace it with a
// transactional shared implementation.
type FileStore struct {
	mu    sync.Mutex
	path  string
	state state
}

func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		return nil, fmt.Errorf("ledger path is empty")
	}
	store := &FileStore{path: path, state: newState()}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &store.state); err != nil {
		return nil, fmt.Errorf("decode ledger: %w", err)
	}
	if store.state.Reservations == nil {
		store.state.Reservations = make(map[string]Reservation)
	}
	if store.state.Claims == nil {
		store.state.Claims = make(map[string]bool)
	}
	// A process cannot prove that a signing operation which was persisted as
	// Signing completed after a restart. Make that unknown outcome retryable;
	// the stable operation ID lets an idempotent KMS recover the exact result.
	for operationID, reservation := range store.state.Reservations {
		if reservation.State != Signing {
			continue
		}
		reservation.State = RetryableFailure
		reservation.Failure = "signing outcome was unknown across process restart"
		store.state.Reservations[operationID] = reservation
	}
	return store, nil
}

func (s *FileStore) Reserve(_ context.Context, key ReservationKey) (Reservation, error) {
	if s == nil {
		return Reservation{}, fmt.Errorf("ledger is nil")
	}
	if err := validateKey(key); err != nil {
		return Reservation{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := cloneState(s.state)
	reservation, err := reserveLocked(&s.state, key)
	if err != nil {
		return Reservation{}, err
	}
	if err := s.persistLocked(); err != nil {
		s.state = previous
		return Reservation{}, err
	}
	return reservation, nil
}

func (s *FileStore) MarkSigning(_ context.Context, operationID string) error {
	if s == nil {
		return fmt.Errorf("ledger is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := cloneState(s.state)
	if err := markSigningLocked(&s.state, operationID); err != nil {
		return err
	}
	if err := s.persistLocked(); err != nil {
		s.state = previous
		return err
	}
	return nil
}

func (s *FileStore) Complete(_ context.Context, operationID string, result Result) error {
	if s == nil {
		return fmt.Errorf("ledger is nil")
	}
	if len(result.Artifact) == 0 || len(result.Response) == 0 {
		return fmt.Errorf("completed ledger result is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := s.state.Reservations[operationID]
	if err := completeLocked(&s.state, operationID, result); err != nil {
		return err
	}
	if err := s.persistLocked(); err != nil {
		s.state.Reservations[operationID] = previous
		return err
	}
	return nil
}

func (s *FileStore) Fail(_ context.Context, operationID string, failureState State, failure error) error {
	if s == nil {
		return fmt.Errorf("ledger is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, ok := s.state.Reservations[operationID]
	if err := failLocked(&s.state, operationID, failureState, failure); err != nil {
		return err
	}
	if err := s.persistLocked(); err != nil {
		if ok {
			s.state.Reservations[operationID] = previous
		}
		return err
	}
	return nil
}

func (s *FileStore) Lookup(_ context.Context, operationID string) (Reservation, bool, error) {
	if s == nil {
		return Reservation{}, false, fmt.Errorf("ledger is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	reservation, ok := s.state.Reservations[operationID]
	return cloneReservation(reservation), ok, nil
}

func (s *FileStore) Revoke(_ context.Context, grantID string) error {
	if s == nil {
		return fmt.Errorf("ledger is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := cloneState(s.state)
	if err := revokeLocked(&s.state, grantID); err != nil {
		return err
	}
	if err := s.persistLocked(); err != nil {
		s.state = previous
		return err
	}
	return nil
}

func (s *FileStore) IsRevoked(_ context.Context, grantID string) (bool, error) {
	if s == nil {
		return false, fmt.Errorf("ledger is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, reservation := range s.state.Reservations {
		if reservation.Key.GrantID == grantID && reservation.State == Revoked {
			return true, nil
		}
	}
	return false, nil
}

func validateKey(key ReservationKey) error {
	if key.GrantID == "" || key.RequestID == "" || key.RequestDigest == "" || key.IdentityRef == "" || key.OperationID == "" || !key.Domain.Valid() {
		return fmt.Errorf("ledger reservation key is incomplete")
	}
	return nil
}

func reserveLocked(s *state, key ReservationKey) (Reservation, error) {
	if existing, ok := s.Reservations[key.OperationID]; ok {
		if !sameKey(existing.Key, key) {
			return Reservation{}, ErrConflict
		}
		if existing.State == Revoked {
			return Reservation{}, ErrRevoked
		}
		if existing.State == Completed || existing.State == PermanentFailure {
			return cloneReservation(existing), nil
		}
		if s.Claims[key.OperationID] {
			return Reservation{}, ErrInProgress
		}
		if existing.State == Signing {
			return Reservation{}, ErrInProgress
		}
		if existing.State == RetryableFailure {
			existing.State = Reserved
			existing.Failure = ""
			s.Reservations[key.OperationID] = existing
		}
		s.Claims[key.OperationID] = true
		existing.Owned = true
		return cloneReservation(existing), nil
	}
	for _, existing := range s.Reservations {
		if existing.Key.GrantID != key.GrantID {
			continue
		}
		if !sameKey(existing.Key, key) {
			return Reservation{}, ErrGrantConsumed
		}
		return Reservation{}, ErrConflict
	}
	reservation := Reservation{Key: key, State: Reserved, Owned: true}
	s.Reservations[key.OperationID] = reservation
	s.Claims[key.OperationID] = true
	return cloneReservation(reservation), nil
}

func markSigningLocked(s *state, operationID string) error {
	reservation, ok := s.Reservations[operationID]
	if !ok {
		return ErrUnknownOperation
	}
	switch reservation.State {
	case Reserved, RetryableFailure:
		reservation.State = Signing
		reservation.Failure = ""
		s.Reservations[operationID] = reservation
		return nil
	case Signing:
		return nil
	case Completed:
		return nil
	case Revoked:
		return ErrRevoked
	default:
		return fmt.Errorf("operation %q is in terminal state %s", operationID, reservation.State)
	}
}

func completeLocked(s *state, operationID string, result Result) error {
	reservation, ok := s.Reservations[operationID]
	if !ok {
		return ErrUnknownOperation
	}
	if reservation.State == Revoked {
		return ErrRevoked
	}
	if reservation.State == Completed {
		if !sameResult(reservation.Result, result) {
			return ErrConflict
		}
		return nil
	}
	if reservation.State != Signing && reservation.State != Reserved {
		return fmt.Errorf("operation %q is not signable in state %s", operationID, reservation.State)
	}
	reservation.State = Completed
	reservation.Result = cloneResult(result)
	reservation.Failure = ""
	delete(s.Claims, operationID)
	s.Reservations[operationID] = reservation
	return nil
}

func failLocked(s *state, operationID string, failureState State, failure error) error {
	if failureState != RetryableFailure && failureState != PermanentFailure {
		return fmt.Errorf("invalid failure state %s", failureState)
	}
	reservation, ok := s.Reservations[operationID]
	if !ok {
		return ErrUnknownOperation
	}
	if reservation.State == Completed {
		return nil
	}
	if reservation.State == Revoked {
		return ErrRevoked
	}
	reservation.State = failureState
	if failure != nil {
		reservation.Failure = failure.Error()
	}
	delete(s.Claims, operationID)
	s.Reservations[operationID] = reservation
	return nil
}

func revokeLocked(s *state, grantID string) error {
	found := false
	for operationID, reservation := range s.Reservations {
		if reservation.Key.GrantID != grantID {
			continue
		}
		found = true
		if reservation.State == Completed {
			return fmt.Errorf("cannot revoke completed Grant %q", grantID)
		}
		reservation.State = Revoked
		delete(s.Claims, operationID)
		s.Reservations[operationID] = reservation
	}
	if !found {
		return fmt.Errorf("Grant %q is not in the ledger", grantID)
	}
	return nil
}

func (s *FileStore) persistLocked() error {
	parent := filepath.Dir(s.path)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(parent, ".ledger-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := json.NewEncoder(temporary).Encode(s.state); err != nil {
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

func sameKey(left, right ReservationKey) bool {
	return left == right
}

func sameResult(left, right Result) bool {
	return string(left.Artifact) == string(right.Artifact) && string(left.Response) == string(right.Response) && left.KeyID == right.KeyID && left.Generation == right.Generation && left.Algorithm == right.Algorithm
}

func cloneResult(result Result) Result {
	result.Artifact = append([]byte(nil), result.Artifact...)
	result.Response = append([]byte(nil), result.Response...)
	return result
}

func cloneReservation(reservation Reservation) Reservation {
	reservation.Result = cloneResult(reservation.Result)
	return reservation
}

func cloneState(value state) state {
	copyValue := newState()
	for key, reservation := range value.Reservations {
		copyValue.Reservations[key] = cloneReservation(reservation)
	}
	for key, claimed := range value.Claims {
		copyValue.Claims[key] = claimed
	}
	return copyValue
}
