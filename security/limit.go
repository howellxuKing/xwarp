package security

import (
	"sync"
	"time"
)

type limitEntry struct {
	Count int
	Until time.Time
}
type Limiter struct {
	mu        sync.Mutex
	entries   map[string]limitEntry
	nextSweep time.Time
}

func NewLimiter() *Limiter { return &Limiter{entries: make(map[string]limitEntry)} }

// Allow uses a bounded table and fixed expiry, so rejected attempts never extend a lock.
func (l *Limiter) Allow(key string, limit int, window time.Duration, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !now.Before(l.nextSweep) {
		for key, entry := range l.entries {
			if !now.Before(entry.Until) {
				delete(l.entries, key)
			}
		}
		l.nextSweep = now.Add(time.Minute)
	}
	e, exists := l.entries[key]
	if !exists || !now.Before(e.Until) {
		if !exists && len(l.entries) >= 10000 {
			return false
		}
		e = limitEntry{Until: now.Add(window)}
	}
	if e.Count >= limit {
		return false
	}
	e.Count++
	l.entries[key] = e
	return true
}
