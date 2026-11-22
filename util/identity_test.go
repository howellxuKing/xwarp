package util

import (
	"errors"
	"testing"
)

func TestMaskTrafficRankNameKeepsShortNamesFromPanicking(t *testing.T) {
	cases := map[string]string{
		"":     "****",
		"a":    "a****",
		"ab":   "ab****ab",
		"abcd": "ab****cd",
		"用户":   "用户****用户",
	}
	for name, want := range cases {
		got := MaskTrafficRankName(name)
		if got != want {
			t.Fatalf("mask %q = %q, want %q", name, got, want)
		}
	}
}

func TestSameOrValidUsernameKeepsExistingShortNames(t *testing.T) {
	if err := SameOrValidUsername("a", "a"); err != nil {
		t.Fatal(err)
	}
	if err := SameOrValidUsername("short", "short"); err != nil {
		t.Fatal(err)
	}
	if err := SameOrValidUsername("a", "validname"); err != nil {
		t.Fatal(err)
	}
	if err := SameOrValidUsername("validname", "ab"); err == nil {
		t.Fatal("a renamed short username was accepted")
	}
	if err := SameOrValidUsername("validname", "bad name"); err == nil {
		t.Fatal("a non alphanumeric username was accepted")
	}
}

func TestFinishRemoteThenLocalSkipsLocalDeleteAfterCoreFailure(t *testing.T) {
	localCalled := false
	remoteErr := errors.New("core unreachable")
	err := FinishRemoteThenLocal(func() error { return remoteErr }, func() error {
		localCalled = true
		return nil
	})
	if err != remoteErr || localCalled {
		t.Fatalf("local delete ran or error changed: called=%v err=%v", localCalled, err)
	}
	localCalled = false
	if err := FinishRemoteThenLocal(func() error { return nil }, func() error {
		localCalled = true
		return nil
	}); err != nil || !localCalled {
		t.Fatal("successful core removal did not continue to the local delete")
	}
}
