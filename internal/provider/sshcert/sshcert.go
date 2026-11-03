// Package sshcert hands an agent the SSH certificate the human granted it
// with geas ssh grant: it copies the agent's key and certificate into the
// session directory, so that a sandbox need only grant that directory, and
// writes an ssh_config that uses them. It watches the agent's directory, so
// that a grant made while the session runs reaches the agent within seconds.
//
// Each session reserves a name of its own for its agent before the harness
// starts, recorded in the ledger, and revoking that entry removes the
// agent's directory, its key and certificate: a certificate expires on its
// own, within 12 hours, but nothing is left to use it. A name the human
// pinned is the human's, and stays.
package sshcert

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/nolith/geas/internal/ledger"
	"github.com/nolith/geas/internal/provider"
	"github.com/nolith/geas/internal/secretfile"
	"github.com/nolith/geas/internal/sessiondir"
	"github.com/nolith/geas/internal/sshgrant"
	"github.com/nolith/geas/internal/timing"
)

// ID is the provider's ID and kind: a session has one at most.
const ID = "ssh"

// pollInterval is how often Watch looks at the agent's directory: a stat of
// three files, cheap enough to run every few seconds for a whole session.
const pollInterval = 3 * time.Second

// reserveAttempts is how many new names Reserve draws before it gives up:
// with 40 random bits, a second is already as unlikely as can be.
const reserveAttempts = 5

// Provider is the agent's certificate, for one session.
type Provider struct {
	// Name is the agent's name; empty when New could not find it, or
	// Reserve could not reserve it.
	Name string
	// tool and dir are what a new name is made of; reserve, whether the
	// session reserves Name, which the human did not pin.
	tool, dir string
	reserve   bool
	// session is the ID of the session whose names Revoke removes.
	session string
	// agents is the agents' directory, $XDG_STATE_HOME/geas/agents.
	agents string
	poll   time.Duration
	now    func() time.Time
}

var (
	_ provider.Provider = (*Provider)(nil)
	_ provider.Watcher  = (*Provider)(nil)
	_ provider.Reserver = (*Provider)(nil)
)

// New prepares the certificate of the agent harness runs, whose tool is the
// base name of its first word. When AGENT_SSH_NAME names an agent of that
// tool, as the human may pin one, or a nested session inherits it, that is
// the agent; otherwise the provider draws a new name, which Reserve makes
// the session's. When there is no name, the provider is returned all the
// same, for its Setup, with the reason.
func New(harness []string) (*Provider, error) {
	p := &Provider{poll: pollInterval, now: time.Now}
	agents, err := sshgrant.AgentsDir()
	if err != nil {
		return p, err
	}
	p.agents = agents
	if len(harness) == 0 {
		return p, errors.New("no harness to name the agent after")
	}
	tool := filepath.Base(harness[0])
	if p.Name = sshgrant.Pinned(tool); p.Name != "" {
		return p, nil
	}
	// Without a working directory, the name goes without that part.
	dir, _ := os.Getwd()
	if p.Name, err = sshgrant.NewName(tool, dir); err != nil {
		return p, err
	}
	p.tool, p.dir, p.reserve = tool, dir, true
	return p, nil
}

// NewRevoker is the provider that revokes what session reserved, for the
// reaper, which has nothing else to build it from.
func NewRevoker(session string) *Provider {
	return &Provider{session: session, poll: pollInterval, now: time.Now}
}

func (p *Provider) ID() string   { return ID }
func (p *Provider) Kind() string { return ID }

// Setup exports the agent's name as AGENT_SSH_NAME, and protects every
// agent's key: the agent reads its own copy in the session directory.
func (p *Provider) Setup() provider.Setup {
	s := provider.Setup{Env: map[string]string{}}
	if p.Name != "" {
		s.Env["AGENT_SSH_NAME"] = p.Name
	}
	if p.agents != "" {
		s.Protect = []string{p.agents}
	}
	return s
}

// Acquire copies the agent's key and certificate, once the certificate is
// valid and for that key.
func (p *Provider) Acquire(context.Context, *ledger.Ledger) (provider.Credential, error) {
	return p.load()
}

// Refresh returns c: the session watches the agent's directory instead.
func (p *Provider) Refresh(_ context.Context, c provider.Credential) (provider.Credential, error) {
	return c, nil
}

// Reserve makes the drawn name the session's, before the harness starts,
// so that Setup exports it: each attempt is in the ledger before the
// agent's directory is created, and a name that is taken is closed and
// replaced by a new one. A pinned name needs nothing. When no name can be
// reserved, the provider is left without one.
func (p *Provider) Reserve(l *ledger.Ledger) error {
	if !p.reserve {
		return nil
	}
	// Set first: whatever an attempt cut short left, Revoke removes.
	p.session = l.ID()
	err := p.reserveName(l)
	if err != nil {
		p.Name = ""
	}
	return err
}

func (p *Provider) reserveName(l *ledger.Ledger) error {
	owner := sshgrant.Owner{Session: p.session, Tool: p.tool, Dir: p.dir}
	for attempt := 0; attempt < reserveAttempts; attempt++ {
		if attempt > 0 {
			name, err := sshgrant.NewName(p.tool, p.dir)
			if err != nil {
				return err
			}
			p.Name = name
		}
		e := ledger.Entry{Provider: ID, Name: p.Name, Created: p.now().UTC()}
		if err := l.Record(e); err != nil {
			return err
		}
		err := sshgrant.Reserve(p.Name, owner)
		if !errors.Is(err, sshgrant.ErrTaken) {
			return err
		}
		// Someone else's: nothing of it is the session's to remove.
		e.Revoked = true
		if err = l.Record(e); err != nil {
			return err
		}
	}
	return errors.New("no free agent name after " + fmt.Sprint(reserveAttempts) + " attempts")
}

// Revoke removes the session's copies of the key and certificate, and the
// directory of the agent e names, once the session reserved it: a name
// that is not the session's, or gone already, is ErrGone, and stays.
func (p *Provider) Revoke(_ context.Context, e ledger.Entry) error {
	if p.session == "" {
		return ledger.ErrGone
	}
	if dir, err := sessiondir.Open(p.session); err == nil {
		for _, rel := range []string{sshgrant.SessionConfig, sshgrant.SessionCertificate, sshgrant.SessionKey} {
			if err = dir.RemoveFile(rel); err != nil {
				return err
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	err := sshgrant.Release(e.Name, p.session)
	if errors.Is(err, sshgrant.ErrNotOwned) {
		return ledger.ErrGone
	}
	return err
}

// ask is what the agent should do about a missing or unusable certificate.
func (p *Provider) ask() string {
	return "ask the human: geas ssh grant " + p.Name + " <host>"
}

// load reads the agent's key and certificate, as a credential whose files
// go into the session directory.
func (p *Provider) load() (provider.Credential, error) {
	dir := filepath.Join(p.agents, p.Name)
	key, err := secretfile.Read(filepath.Join(dir, sshgrant.KeyFile))
	if errors.Is(err, os.ErrNotExist) {
		return provider.Credential{}, errors.New(p.Name + " has no key yet: " + p.ask())
	}
	if err != nil {
		return provider.Credential{}, err
	}
	pub, err := secretfile.Read(filepath.Join(dir, sshgrant.PublicKeyFile))
	if err != nil {
		return provider.Credential{}, err
	}
	raw, err := secretfile.Read(filepath.Join(dir, sshgrant.CertificateFile))
	if errors.Is(err, os.ErrNotExist) {
		return provider.Credential{}, errors.New(p.Name + " has no certificate yet: " + p.ask())
	}
	if err != nil {
		return provider.Credential{}, err
	}
	cert, err := sshgrant.ParseCertificate(raw)
	if err != nil {
		return provider.Credential{}, fmt.Errorf("the certificate of %s is unusable, %v: %s", p.Name, err, p.ask())
	}
	if !cert.ForKey(pub) {
		return provider.Credential{}, errors.New("the certificate of " + p.Name + " is not for its key: " + p.ask())
	}
	if now := p.now(); !cert.ValidAt(now) {
		if expires := cert.Expires(); !expires.IsZero() && !now.Before(expires) {
			return provider.Credential{}, errors.New("the certificate of " + p.Name + " expired at " + expires.Format("2006-01-02 15:04 MST") + ": " + p.ask())
		}
		return provider.Credential{}, errors.New("the certificate of " + p.Name + " is not valid yet: " + p.ask())
	}
	return provider.Credential{
		Expires: cert.Expires(),
		Files:   map[string][]byte{sshgrant.SessionKey: key, sshgrant.SessionCertificate: raw},
	}, nil
}

// stamp is what Watch compares between two looks at the agent's directory:
// each file's identity, size and modification time.
type stamp [3]struct {
	ino, size int64
	mod       time.Time
}

func (p *Provider) stamp() stamp {
	var s stamp
	dir := filepath.Join(p.agents, p.Name)
	for i, name := range []string{sshgrant.KeyFile, sshgrant.PublicKeyFile, sshgrant.CertificateFile} {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		s[i].size, s[i].mod = info.Size(), info.ModTime()
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			s[i].ino = int64(stat.Ino)
		}
	}
	return s
}

// Watch looks at the agent's directory every few seconds, and reads it
// again whenever a file there changed: a new grant returns the new
// certificate; while the session holds one, a certificate that expired or
// was dropped returns why.
func (p *Provider) Watch(ctx context.Context, held provider.Credential) (provider.Credential, error) {
	holding := held.Files != nil
	var seen stamp
	for first := true; ; first = false {
		if holding && !held.Expires.IsZero() && !p.now().Before(held.Expires) {
			return provider.Credential{}, errors.New("the certificate of " + p.Name + " expired at " + held.Expires.Format("2006-01-02 15:04 MST") + ": " + p.ask())
		}
		if s := p.stamp(); first || s != seen {
			seen = s
			c, err := p.load()
			switch {
			case err == nil && !same(c, held):
				return c, nil
			case err != nil && holding:
				return provider.Credential{}, err
			}
		}
		if err := timing.SleepContext(ctx, p.poll); err != nil {
			return provider.Credential{}, err
		}
	}
}

// same reports whether a and b carry the same files.
func same(a, b provider.Credential) bool {
	if len(a.Files) != len(b.Files) {
		return false
	}
	for name, raw := range a.Files {
		if other, ok := b.Files[name]; !ok || !bytes.Equal(raw, other) {
			return false
		}
	}
	return true
}
