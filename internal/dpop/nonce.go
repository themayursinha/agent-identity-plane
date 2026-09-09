package dpop

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"
)

// NonceHeader is the RFC 9449 DPoP-Nonce response header.
const NonceHeader = "DPoP-Nonce"

// NonceTTL is how long an issued nonce remains acceptable.
const NonceTTL = 2 * time.Minute

// NonceCache holds unguessable, single-use DPoP nonces in process
// memory. Restart forgets them, so a proof captured before restart
// cannot be replayed from a lost `-dpop-replay` log.
type NonceCache struct {
	mu     sync.Mutex
	issued map[string]int64
	now    func() time.Time
}

// NewNonceCache returns an empty nonce cache.
func NewNonceCache(now func() time.Time) *NonceCache {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &NonceCache{issued: map[string]int64{}, now: now}
}

// Issue stores a new nonce until NonceTTL.
func (c *NonceCache) Issue(now time.Time) string {
	if c == nil {
		return ""
	}
	if now.IsZero() {
		now = c.now()
	}
	var b [16]byte
	_, _ = rand.Read(b[:])
	n := "n-" + hex.EncodeToString(b[:])
	until := now.Add(NonceTTL).Unix()
	c.mu.Lock()
	c.gcLocked(now.Unix())
	c.issued[n] = until
	c.mu.Unlock()
	return n
}

// Has reports whether nonce is still unconsumed and unexpired.
func (c *NonceCache) Has(nonce string, now time.Time) bool {
	if c == nil || strings.TrimSpace(nonce) == "" {
		return false
	}
	if now.IsZero() {
		now = c.now()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	until, ok := c.issued[nonce]
	return ok && until >= now.Unix()
}

// Consume removes a valid nonce. False if missing, expired, or already used.
func (c *NonceCache) Consume(nonce string, now time.Time) bool {
	if c == nil || strings.TrimSpace(nonce) == "" {
		return false
	}
	if now.IsZero() {
		now = c.now()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	until, ok := c.issued[nonce]
	if !ok || until < now.Unix() {
		delete(c.issued, nonce)
		return false
	}
	delete(c.issued, nonce)
	return true
}

func (c *NonceCache) gcLocked(nowUnix int64) {
	for n, until := range c.issued {
		if until < nowUnix {
			delete(c.issued, n)
		}
	}
}

// NonceFromChallenge returns the DPoP-Nonce when the response is an
// RFC 9449 use_dpop_nonce challenge.
func NonceFromChallenge(resp *http.Response) string {
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		return ""
	}
	if !strings.Contains(resp.Header.Get("WWW-Authenticate"), "use_dpop_nonce") {
		return ""
	}
	return strings.TrimSpace(resp.Header.Get(NonceHeader))
}
