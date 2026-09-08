package sts

import (
	"fmt"
	"sync"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/registry"
	"github.com/themayursinha/agent-identity-plane/internal/token"
)

// Reloader atomically replaces registry and signing material from disk.
// A failed load leaves the previous snapshot in place (AI14).
type Reloader struct {
	RegistryPath string
	SigningPath  string
	cfg          *Config
}

func NewReloader(cfg *Config, registryPath, signingPath string) *Reloader {
	return &Reloader{RegistryPath: registryPath, SigningPath: signingPath, cfg: cfg}
}

func (r *Reloader) Reload() error {
	if r == nil || r.cfg == nil {
		return fmt.Errorf("sts: reloader not configured")
	}
	var reg *registry.Registry
	var kr *token.Keyring
	var err error
	if r.RegistryPath != "" {
		reg, err = registry.LoadFile(r.RegistryPath)
		if err != nil {
			r.cfg.Metrics.ReloadFails.Add(1)
			return err
		}
	}
	if r.SigningPath != "" {
		kr, err = token.LoadSigningFile(r.SigningPath)
		if err != nil {
			r.cfg.Metrics.ReloadFails.Add(1)
			return err
		}
	}
	if reg != nil || kr != nil {
		if err := r.cfg.installIdentity(reg, kr); err != nil {
			r.cfg.Metrics.ReloadFails.Add(1)
			return err
		}
	}
	r.cfg.Metrics.Reloads.Add(1)
	return nil
}

type tokenBucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
	rate   float64
	burst  float64
}

func newTokenBucket(rate float64) *tokenBucket {
	if rate <= 0 {
		return nil
	}
	burst := rate
	if burst < 1 {
		burst = 1
	}
	return &tokenBucket{tokens: burst, last: time.Now(), rate: rate, burst: burst}
}

func (b *tokenBucket) allow() bool {
	if b == nil {
		return true
	}
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	b.tokens += elapsed * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
