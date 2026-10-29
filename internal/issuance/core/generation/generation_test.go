package generation

import "testing"

func TestGenerationRotationStateMachine(t *testing.T) {
	registry, err := NewRegistry([]Metadata{{Generation: "old", KeyID: "old-key", Algorithm: "RS256", State: Active}, {Generation: "new", KeyID: "new-key", Algorithm: "RS256", State: Prepared}})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.SetState("old", Renewing); err != nil {
		t.Fatal(err)
	}
	if err := registry.SetState("new", Active); err != nil {
		t.Fatal("failed to activate the next generation during overlap:", err)
	}
	if err := registry.SetState("old", Draining); err != nil {
		t.Fatal(err)
	}
	if err := registry.SetState("old", Retired); err != nil {
		t.Fatal(err)
	}
	if err := registry.SetState("new", Active); err != nil {
		t.Fatal(err)
	}
}
