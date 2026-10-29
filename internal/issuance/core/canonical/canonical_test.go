package canonical

import "testing"

func TestCanonicalizeSortsKeysAndNormalizesNumbers(t *testing.T) {
	got, err := Canonicalize([]byte(`{"b":1.0,"a":"<"}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":"<","b":1}` {
		t.Fatalf("canonical JSON = %s", got)
	}
}

func TestCanonicalizeRejectsDuplicateKeysAndTrailingValues(t *testing.T) {
	if _, err := Canonicalize([]byte(`{"a":1,"a":2}`)); err == nil {
		t.Fatal("accepted duplicate object key")
	}
	if _, err := Canonicalize([]byte(`{"a":1} true`)); err == nil {
		t.Fatal("accepted trailing JSON value")
	}
}
