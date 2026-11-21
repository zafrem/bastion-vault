package exceptions

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

// Client is the module-side exception store. It is designed to work on its
// own: enforcement reads only the local, signature-verified store, so a module
// keeps its last known exceptions when Tracker or NATS is down, and with no
// exceptions at all it simply enforces every rule. No public key configured
// means the feature is off and nothing is ever exempted.
//
// Exceptions arrive over NATS, or can be dropped into the persisted file by an
// operator (for example an envelope exported from Tracker for an air-gapped
// module). Either way an envelope is only trusted if its signature verifies.
type Client struct {
	module string
	pubs   []ed25519.PublicKey
	path   string

	mu   sync.RWMutex
	byID map[string]Exception
	envs []Envelope

	nc       *nats.Conn
	stop     chan struct{}
	stopped  sync.Once
	lastMod  time.Time
	onChange func()
}

// NewClient creates a Client for module. pubKeys is the base64 Ed25519 public
// key published by Tracker, or a comma-separated list while a key is being
// rotated; empty disables the feature. path is where signed envelopes are
// persisted ("" keeps them in memory only).
func NewClient(module, pubKeys, path string) (*Client, error) {
	c := &Client{module: module, path: path, byID: map[string]Exception{}, stop: make(chan struct{})}
	keys, err := ParsePublicKeys(pubKeys)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return c, nil
	}
	c.pubs = keys
	c.loadFile()
	return c, nil
}

// SetOnChange registers a callback run after the exception set changes, for
// example to flush a result cache so a revocation takes effect immediately.
func (c *Client) SetOnChange(f func()) {
	c.mu.Lock()
	c.onChange = f
	c.mu.Unlock()
}

func (c *Client) notifyChange() {
	c.mu.RLock()
	f := c.onChange
	c.mu.RUnlock()
	if f != nil {
		f()
	}
}

// Enabled reports whether a public key is configured.
func (c *Client) Enabled() bool { return c != nil && len(c.pubs) > 0 }

// Allowed reports whether an active exception exempts rule for this caller,
// returning its ID so the caller can record which exception was used.
func (c *Client) Allowed(rule, tenant, user string) (string, bool) {
	if !c.Enabled() {
		return "", false
	}
	now := time.Now()
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, e := range c.byID {
		if e.Applies(c.module, rule, tenant, user, now) {
			return e.ID, true
		}
	}
	return "", false
}

// List returns every known exception (including revoked and expired ones).
func (c *Client) List() []Exception {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Exception, 0, len(c.byID))
	for _, e := range c.byID {
		out = append(out, e)
	}
	return out
}

// Apply verifies an envelope, merges it and persists it. Changes are ordered
// by per-exception version, so replaying an old message cannot undo a newer
// change such as a revocation.
func (c *Client) Apply(env Envelope) error {
	if !c.Enabled() {
		return errors.New("exceptions: disabled (no public key)")
	}
	p, err := Verify(c.pubs, env)
	if err != nil {
		return err
	}
	c.mu.Lock()
	changed := c.merge(p)
	if changed {
		c.envs = append(c.envs, env)
		c.prune(time.Now())
		c.persistLocked()
	}
	c.mu.Unlock()
	if changed {
		c.notifyChange()
	}
	return nil
}

// merge folds p into byID and reports whether anything was newer.
func (c *Client) merge(p Payload) bool {
	changed := false
	for _, e := range p.Exceptions {
		if cur, ok := c.byID[e.ID]; ok && cur.Version >= e.Version {
			continue
		}
		c.byID[e.ID] = e
		changed = true
	}
	return changed
}

// prune drops envelopes whose every exception is superseded or expired.
func (c *Client) prune(now time.Time) {
	kept := c.envs[:0]
	for _, env := range c.envs {
		var p Payload
		if json.Unmarshal(env.Payload, &p) != nil {
			continue
		}
		for _, e := range p.Exceptions {
			if cur := c.byID[e.ID]; cur.Version == e.Version && now.Before(e.ExpiresAt) {
				kept = append(kept, env)
				break
			}
		}
	}
	c.envs = kept
	for id, e := range c.byID {
		if !now.Before(e.ExpiresAt) {
			delete(c.byID, id) // expired exceptions are inert; a replay is rejected by Active()
		}
	}
}

func (c *Client) persistLocked() {
	if c.path == "" {
		return
	}
	data, err := json.Marshal(c.envs)
	if err == nil {
		err = writeFileAtomic(c.path, data)
	}
	if err != nil {
		log.Printf("[exceptions] could not persist %s: %v", c.path, err)
	}
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".exceptions-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// loadFile merges every envelope in the persisted file whose signature
// verifies. Anything else is ignored, so editing the file by hand cannot
// create an exception.
func (c *Client) loadFile() {
	if c.path == "" {
		return
	}
	st, err := os.Stat(c.path)
	if err != nil {
		return
	}
	data, err := os.ReadFile(c.path)
	if err != nil {
		log.Printf("[exceptions] cannot read %s: %v", c.path, err)
		return
	}
	var envs []Envelope
	if err := json.Unmarshal(data, &envs); err != nil {
		// Also accept a single exported envelope.
		var one Envelope
		if json.Unmarshal(data, &one) != nil || len(one.Payload) == 0 {
			log.Printf("[exceptions] ignoring unreadable %s", c.path)
			return
		}
		envs = []Envelope{one}
	}
	c.mu.Lock()
	changed := false
	for _, env := range envs {
		p, err := Verify(c.pubs, env)
		if err != nil {
			log.Printf("[exceptions] ignoring envelope in %s: %v", c.path, err)
			continue
		}
		if c.merge(p) {
			c.envs = append(c.envs, env)
			changed = true
		}
	}
	c.prune(time.Now())
	c.lastMod = st.ModTime()
	c.mu.Unlock()
	if changed {
		c.notifyChange()
	}
}

// Start connects to NATS (if natsURL is set) and watches the file for
// operator-supplied envelopes. It never blocks and never fails startup: with
// NATS unreachable the module keeps running on its local store and picks up
// updates when the bus returns.
func (c *Client) Start(natsURL string, filePoll time.Duration) {
	if !c.Enabled() {
		return
	}
	if natsURL != "" {
		c.connect(natsURL)
	}
	if c.path != "" && filePoll > 0 {
		go c.watchFile(filePoll)
	}
}

func (c *Client) connect(url string) {
	nc, err := nats.Connect(url,
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(5*time.Second),
		nats.ConnectHandler(func(nc *nats.Conn) { go c.requestSnapshot(nc) }),
		nats.ReconnectHandler(func(nc *nats.Conn) { go c.requestSnapshot(nc) }),
	)
	if err != nil {
		log.Printf("[exceptions] nats unavailable (%v); using local exceptions only", err)
		return
	}
	if _, err := nc.Subscribe(SubjectUpdates, func(m *nats.Msg) {
		var env Envelope
		if err := json.Unmarshal(m.Data, &env); err != nil {
			return
		}
		if err := c.Apply(env); err != nil {
			log.Printf("[exceptions] rejected update: %v", err)
		}
	}); err != nil {
		log.Printf("[exceptions] subscribe failed: %v", err)
	}
	c.nc = nc
}

// requestSnapshot asks Tracker for the full set, covering anything missed
// while this module was down or disconnected.
func (c *Client) requestSnapshot(nc *nats.Conn) {
	msg, err := nc.Request(SubjectSnapshot, nil, 3*time.Second)
	if err != nil {
		log.Printf("[exceptions] no snapshot from tracker (%v); keeping local exceptions", err)
		return
	}
	var env Envelope
	if err := json.Unmarshal(msg.Data, &env); err != nil {
		return
	}
	if err := c.Apply(env); err != nil {
		log.Printf("[exceptions] rejected snapshot: %v", err)
	}
}

func (c *Client) watchFile(every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			if st, err := os.Stat(c.path); err == nil && st.ModTime().After(c.lastMod) {
				c.loadFile()
			}
		}
	}
}

// Close stops background work and the NATS connection.
func (c *Client) Close() {
	if c == nil {
		return
	}
	c.stopped.Do(func() { close(c.stop) })
	if c.nc != nil {
		c.nc.Close()
	}
}

// String summarises the client for logs.
func (c *Client) String() string {
	if !c.Enabled() {
		return "exceptions: disabled"
	}
	return fmt.Sprintf("exceptions: module=%s file=%q", c.module, c.path)
}
