package ledger

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	v1 "github.com/dinoallo/k8s-credential-issuance/api/grant/v1"
)

func testKey() ReservationKey {
	return ReservationKey{GrantID: "grant-1", Domain: v1.DomainSA, RequestID: "request-1", RequestDigest: "sha256:binding", IdentityRef: "worker-1", OperationID: "operation-1"}
}

func TestFileStoreMakesUnknownSigningOutcomeRetryableAfterRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reserve(context.Background(), testKey()); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkSigning(context.Background(), "operation-1"); err != nil {
		t.Fatal(err)
	}

	restarted, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := restarted.Reserve(context.Background(), testKey())
	if err != nil {
		t.Fatal(err)
	}
	if !reservation.Owned || reservation.State != Reserved {
		t.Fatalf("restart did not reclaim unknown signing outcome: %#v", reservation)
	}
}

func TestConcurrentReserveHasOneOwner(t *testing.T) {
	store := NewMemoryStore()
	var wait sync.WaitGroup
	var mu sync.Mutex
	owners := 0
	errors := 0
	for i := 0; i < 16; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			reservation, err := store.Reserve(context.Background(), testKey())
			mu.Lock()
			defer mu.Unlock()
			if err == nil && reservation.Owned {
				owners++
			}
			if err != nil && err != ErrInProgress {
				errors++
			}
		}()
	}
	wait.Wait()
	if owners != 1 || errors != 0 {
		t.Fatalf("owners=%d unexpected_errors=%d", owners, errors)
	}
	if err := store.MarkSigning(context.Background(), "operation-1"); err != nil {
		t.Fatal(err)
	}
	result := Result{Artifact: []byte("artifact"), Response: []byte("response"), KeyID: "key-1", Generation: "generation-1", Algorithm: "RS256"}
	if err := store.Complete(context.Background(), "operation-1", result); err != nil {
		t.Fatal(err)
	}
	reservation, ok, err := store.Lookup(context.Background(), "operation-1")
	if err != nil || !ok || reservation.State != Completed || string(reservation.Result.Response) != "response" {
		t.Fatalf("unexpected completed reservation: %#v %v %v", reservation, ok, err)
	}
}
