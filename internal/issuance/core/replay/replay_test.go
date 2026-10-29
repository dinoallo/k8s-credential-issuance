package replay

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestMemoryStoreConsumesEachKeyOnce(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := NewMemoryStore(func() time.Time { return now })
	if err := store.Consume(context.Background(), "identity:nonce", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := store.Consume(context.Background(), "identity:nonce", now.Add(time.Hour)); !errors.Is(err, ErrAlreadyConsumed) {
		t.Fatalf("second consume error = %v, want ErrAlreadyConsumed", err)
	}
}

func TestFileStoreRecoversConsumedKeysAfterRestart(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	path := filepath.Join(t.TempDir(), "replay.json")
	store, err := NewFileStore(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Consume(context.Background(), "identity:nonce", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewFileStore(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Consume(context.Background(), "identity:nonce", now.Add(time.Hour)); !errors.Is(err, ErrAlreadyConsumed) {
		t.Fatalf("restarted consume error = %v, want ErrAlreadyConsumed", err)
	}
}

func TestMemoryStoreRejectsExpiredReservations(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := NewMemoryStore(func() time.Time { return now })
	if err := store.Consume(context.Background(), "identity:nonce", now); !errors.Is(err, ErrInvalidExpiry) {
		t.Fatalf("expired consume error = %v, want ErrInvalidExpiry", err)
	}
}
