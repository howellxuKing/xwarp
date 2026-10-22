package domesticrules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestOfflineDefaultAndUpdateRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domestic.json")
	store := Open(path)
	base := "rules:\n  - DOMAIN-SUFFIX,openai.com,PROXY\n  - GEOIP,CN,DIRECT\n  - MATCH,PROXY\n"
	before := store.Apply(base)
	if strings.Contains(before, "DOMAIN-SUFFIX,baidu,DIRECT") || strings.Contains(before, "DOMAIN-SUFFIX,com,DIRECT") {
		t.Fatal("an entire top-level domain became direct")
	}
	if !strings.Contains(before, "DOMAIN-SUFFIX,douyin.com,DIRECT") || !strings.HasSuffix(before, "MATCH,PROXY\n") {
		t.Fatal("offline bundled routing unavailable")
	}
	if strings.Index(before, "openai.com,PROXY") > strings.Index(before, "douyin.com,DIRECT") || strings.Index(before, "douyin.com,DIRECT") > strings.Index(before, "GEOIP,CN") {
		t.Fatal("domestic rules bypassed explicit overseas policy or IP fallback")
	}
	var body atomic.Value
	body.Store(bundled + "\n+.new-fixture.example\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body.Load().(string))) }))
	defer server.Close()
	if err := store.Refresh(context.Background(), server.Client(), server.URL); err != nil {
		t.Fatal(err)
	}
	after := store.Apply(base)
	if !strings.Contains(after, "DOMAIN-SUFFIX,new-fixture.example,DIRECT") || store.Version() == Open("").Version() {
		t.Fatal("accepted update did not become active")
	}
	if Open(path).Apply(base) != after {
		t.Fatal("restart did not recover persisted snapshot")
	}
	for _, invalid := range []string{"<html>upstream error</html>", "+.com\n", bundled + "\n+.bad.example,PROXY\n", strings.Repeat("x", maxBytes+1)} {
		body.Store(invalid)
		if store.Refresh(context.Background(), server.Client(), server.URL) == nil {
			t.Fatal("invalid upstream update accepted")
		}
		if store.Apply(base) != after || Open(path).Apply(base) != after {
			t.Fatal("failed refresh replaced last good rules")
		}
	}
	if err := os.WriteFile(path, []byte("broken cache"), 0600); err != nil {
		t.Fatal(err)
	}
	if Open(path).Apply(base) != before {
		t.Fatal("corrupt cache prevented bundled fallback")
	}
}

func TestFailedPersistenceAndConcurrentRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	store := Open(filepath.Join(path, "cache.json"))
	before := store.Version()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(bundled + "\n+.new-fixture.example\n"))
	}))
	defer server.Close()
	if store.Refresh(context.Background(), server.Client(), server.URL) == nil || store.Version() != before {
		t.Fatal("failed persistence activated an unpersisted update")
	}
	store = Open(filepath.Join(t.TempDir(), "cache.json"))
	var readers sync.WaitGroup
	for i := 0; i < 8; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for j := 0; j < 100; j++ {
				if !strings.HasSuffix(store.Apply("rules:\n  - GEOIP,CN,DIRECT\n  - MATCH,PROXY\n"), "MATCH,PROXY\n") {
					t.Error("concurrent read returned incomplete subscription")
				}
			}
		}()
	}
	if err := store.Refresh(context.Background(), server.Client(), server.URL); err != nil {
		t.Fatal(err)
	}
	readers.Wait()
}
