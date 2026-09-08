package sts

import (
	"sync"
	"time"
)

// ReplayCache records STS-issued subject token jtis so they cannot be
// exchanged twice within their remaining lifetime (AI12).
type ReplayCache struct {
	mu   sync.Mutex
	seen map[string]int64
	now  func() time.Time
}

func NewReplayCache(now func() time.Time) *ReplayCache {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &ReplayCache{seen: map[string]int64{}, now: now}
}

// Consume records jti until exp. A second Consume before exp is a replay.
func (c *ReplayCache) Consume(jti string, exp int64) error {
	if c == nil {
		return nil
	}
	if jti == "" {
		return errEmptyJTI
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.purgeLocked(now)
	if until, ok := c.seen[jti]; ok && until > now.Unix() {
		return ErrReplay
	}
	until := exp
	if until <= now.Unix() {
		until = now.Add(120 * time.Second).Unix()
	}
	c.seen[jti] = until
	return nil
}

func (c *ReplayCache) purgeLocked(now time.Time) {
	sec := now.Unix()
	for k, until := range c.seen {
		if until <= sec {
			delete(c.seen, k)
		}
	}
}

type replayError string

func (e replayError) Error() string { return string(e) }

const (
	ErrReplay   = replayError("sts: subject token jti already exchanged")
	errEmptyJTI = replayError("sts: subject token missing jti")
)
