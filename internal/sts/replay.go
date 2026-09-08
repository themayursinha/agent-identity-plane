package sts

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/token"
)

// ReplayCache records STS-issued subject token jtis so they cannot be
// exchanged twice for as long as ValidateTime would still accept them
// (AI12). When opened on a path, consumed jtis survive process restart.
type ReplayCache struct {
	mu   sync.Mutex
	seen map[string]int64
	now  func() time.Time
	file *os.File
}

type replayRecord struct {
	JTI   string `json:"jti"`
	Until int64  `json:"until"`
}

func NewReplayCache(now func() time.Time) *ReplayCache {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &ReplayCache{seen: map[string]int64{}, now: now}
}

// OpenReplayCache loads durable consumed-jti state from path (mode 0600).
func OpenReplayCache(path string, now func() time.Time) (*ReplayCache, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: replay log path required", ErrReplayUnavailable)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := token.CheckSecretFileMode(path); err != nil {
		_ = f.Close()
		return nil, err
	}
	c := NewReplayCache(now)
	c.file = f
	if err := c.recover(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return c, nil
}

func (c *ReplayCache) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.file == nil {
		return nil
	}
	err := c.file.Close()
	c.file = nil
	return err
}

func (c *ReplayCache) recover() error {
	if _, err := c.file.Seek(0, 0); err != nil {
		return err
	}
	sc := bufio.NewScanner(c.file)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	now := c.now().Unix()
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec replayRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return fmt.Errorf("sts: corrupt replay record: %w", err)
		}
		if rec.JTI == "" || rec.Until < now {
			continue
		}
		c.seen[rec.JTI] = rec.Until
	}
	return sc.Err()
}

// Consume records jti through the verification-skew deadline. A second
// Consume before that deadline is a replay. Missing cache or a failed
// durable write fail closed (no mint).
func (c *ReplayCache) Consume(jti string, exp int64) error {
	if c == nil {
		return ErrReplayUnavailable
	}
	if jti == "" {
		return errEmptyJTI
	}
	now := c.now()
	until := token.ReplayUntil(exp)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.purgeLocked(now)
	if stored, ok := c.seen[jti]; ok && stored >= now.Unix() {
		return ErrReplay
	}
	if until < now.Unix() {
		return ErrReplay
	}
	if c.file != nil {
		line, err := json.Marshal(replayRecord{JTI: jti, Until: until})
		if err != nil {
			return err
		}
		line = append(line, '\n')
		if _, err := c.file.Write(line); err != nil {
			return err
		}
		if err := c.file.Sync(); err != nil {
			return err
		}
	}
	c.seen[jti] = until
	return nil
}

func (c *ReplayCache) purgeLocked(now time.Time) {
	sec := now.Unix()
	for k, until := range c.seen {
		if until < sec {
			delete(c.seen, k)
		}
	}
}

type replayError string

func (e replayError) Error() string { return string(e) }

const (
	ErrReplay            = replayError("sts: subject token jti already exchanged")
	ErrReplayUnavailable = replayError("sts: replay cache required")
	errEmptyJTI          = replayError("sts: subject token missing jti")
)
