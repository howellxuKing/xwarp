// Package domesticrules owns offline domestic-domain routing and last-good updates.
package domesticrules

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed data/domestic.list
var bundled string

const SourceURL = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/geolocation-cn.list"
const maxBytes = 512 * 1024

type snapshot struct {
	Content   string    `json:"content"`
	Version   string    `json:"version"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type Store struct {
	mu      sync.RWMutex
	update  sync.Mutex
	path    string
	current snapshot
	rules   string
}

// Open never performs network I/O. Corrupt/missing cache falls back to bundled data.
func Open(path string) *Store {
	rules, err := compile(bundled)
	if err != nil {
		panic("invalid bundled domestic routing data")
	}
	s := &Store{path: path, rules: rules, current: snapshot{Content: bundled, Version: digest(bundled)}}
	if f, err := os.Open(path); err == nil {
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, maxBytes*2+1))
		var cached snapshot
		if err == nil && len(data) <= maxBytes*2 && json.Unmarshal(data, &cached) == nil && cached.Version == digest(cached.Content) {
			if compiled, err := compile(cached.Content); err == nil {
				s.current, s.rules = cached, compiled
			}
		}
	}
	return s
}

// Apply inserts domains after explicit service rules and before the China-IP fallback.
func (s *Store) Apply(base string) string {
	s.mu.RLock()
	rules := s.rules
	s.mu.RUnlock()
	return strings.Replace(base, "  - GEOIP,CN,DIRECT", rules+"  - GEOIP,CN,DIRECT", 1)
}

func (s *Store) Version() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current.Version
}

// Fresh avoids repeated startup downloads; callers retry failures at the next schedule.
func (s *Store) Fresh(now time.Time) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !s.current.UpdatedAt.IsZero() && !s.current.UpdatedAt.After(now) && now.Sub(s.current.UpdatedAt) < 24*time.Hour
}

// Refresh persists a fully validated snapshot before atomically activating it.
// The application supplies a fixed source URL; a client is injectable for isolated tests.
func (s *Store) Refresh(ctx context.Context, client *http.Client, source string) error {
	s.update.Lock()
	defer s.update.Unlock()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download domestic rules: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("domestic rule HTTP status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxBytes {
		return fmt.Errorf("domestic rule response exceeds size limit")
	}
	content := string(data)
	rules, err := compile(content)
	if err != nil {
		return err
	}
	next := snapshot{Content: content, Version: digest(content), UpdatedAt: time.Now().UTC()}
	encoded, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".domestic-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(encoded); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), s.path); err != nil {
		return err
	}
	s.mu.Lock()
	s.current, s.rules = next, rules
	s.mu.Unlock()
	return nil
}

func digest(s string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(s))) }

func compile(content string) (string, error) {
	if len(content) > maxBytes {
		return "", fmt.Errorf("domestic rule data exceeds size limit")
	}
	seen := map[string]bool{}
	var result strings.Builder
	for _, line := range strings.Split(content, "\n") {
		entry := strings.TrimSpace(line)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		kind, domain := "DOMAIN", entry
		if strings.HasPrefix(entry, "+.") {
			kind, domain = "DOMAIN-SUFFIX", strings.TrimPrefix(entry, "+.")
		}
		// Do not turn any entire top-level domain into an automatic direct policy.
		// Upstream includes brand TLDs; preserve the source but omit them from output.
		if kind == "DOMAIN-SUFFIX" && !strings.Contains(domain, ".") && validLabel(domain) {
			continue
		}
		if !validDomain(domain) {
			return "", fmt.Errorf("invalid domestic domain entry")
		}
		key := kind + "," + domain
		if seen[key] {
			continue
		}
		seen[key] = true
		fmt.Fprintf(&result, "  - %s,DIRECT\n", key)
	}
	if len(seen) < 2000 || len(seen) > 20000 {
		return "", fmt.Errorf("domestic domain count outside accepted range")
	}
	return result.String(), nil
}

func validDomain(domain string) bool {
	if len(domain) > 253 || !strings.Contains(domain, ".") || net.ParseIP(domain) != nil {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if !validLabel(label) {
			return false
		}
	}
	return true
}

func validLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, char := range label {
		if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
			return false
		}
	}
	return true
}
