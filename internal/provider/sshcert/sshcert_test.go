package sshcert

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nolith/geas/internal/ledger"
	"github.com/nolith/geas/internal/provider"
	"github.com/nolith/geas/internal/sessiondir"
	"github.com/nolith/geas/internal/sshgrant"
	"github.com/nolith/geas/internal/testutil"
)

// agent is the provider of the agent claude-test, under a new state
// directory, looking at its directory every few milliseconds.
func agent(t *testing.T) (*Provider, string) {
	t.Helper()
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("AGENT_SSH_NAME", "claude-test")
	p, err := New([]string{"/opt/bin/claude", "--resume"})
	if err != nil {
		t.Fatal(err)
	}
	p.poll = 5 * time.Millisecond
	dir, err := sshgrant.AgentDir("claude-test")
	if err != nil {
		t.Fatal(err)
	}
	return p, dir
}

func TestSetup(t *testing.T) {
	p, dir := agent(t)
	s := p.Setup()
	if p.ID() != "ssh" || p.Kind() != "ssh" || p.Name != "claude-test" || len(s.Env) != 1 || s.Env["AGENT_SSH_NAME"] != "claude-test" || len(s.Git) != 0 || !slices.Equal(s.Protect, []string{filepath.Dir(dir)}) {
		t.Fatalf("%+v %+v", p, s)
	}
	// A pinned name is the human's: there is nothing to reserve.
	if err := p.Reserve(nil); err != nil || p.Name != "claude-test" {
		t.Fatal(err)
	}
	// Without a name, the provider still protects every agent's key, and
	// exports nothing.
	p, err := New([]string{"/opt/bin/Claude"})
	if err == nil || err.Error() != "bad tool name: Claude" {
		t.Fatal(err)
	}
	if s = p.Setup(); len(s.Env) != 0 || !slices.Equal(s.Protect, []string{filepath.Dir(dir)}) {
		t.Fatalf("%+v", s)
	}
	if _, err = New(nil); err == nil {
		t.Fatal("named an agent without a harness")
	}
}

func TestAcquire(t *testing.T) {
	p, dir := agent(t)
	ctx := context.Background()
	ask := ": ask the human: geas ssh grant claude-test <host>"
	if _, err := p.Acquire(ctx, nil); err == nil || err.Error() != "claude-test has no key yet"+ask {
		t.Fatal(err)
	}
	// Expired: a grant of 2026-01-01.
	testutil.SSHCertificate(t, dir, "20260101000000:20260101020000", "host:transcoder")
	if _, err := p.Acquire(ctx, nil); err == nil || !strings.HasPrefix(err.Error(), "the certificate of claude-test expired at 2026-01-01 ") || !strings.HasSuffix(err.Error(), ask) {
		t.Fatal(err)
	}
	testutil.SSHCertificate(t, dir, "+1h:+2h", "host:transcoder")
	if _, err := p.Acquire(ctx, nil); err == nil || err.Error() != "the certificate of claude-test is not valid yet"+ask {
		t.Fatal(err)
	}
	testutil.SSHCertificate(t, dir, "-5m:+2h", "host:transcoder")
	c, err := p.Acquire(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := os.ReadFile(filepath.Join(dir, sshgrant.KeyFile))
	cert, _ := os.ReadFile(filepath.Join(dir, sshgrant.CertificateFile))
	if c.Secret != "" || len(c.Files) != 2 || string(c.Files["ssh/id_ed25519"]) != string(key) || string(c.Files["ssh/id_ed25519-cert.pub"]) != string(cert) {
		t.Fatalf("%+v", c)
	}
	if d := time.Until(c.Expires) - 2*time.Hour; d < -time.Minute || d > time.Minute {
		t.Fatalf("expires %v", c.Expires)
	}
	// A certificate for another key is refused.
	other := t.TempDir()
	testutil.SSHCertificate(t, other, "-5m:+2h", "host:transcoder")
	raw, _ := os.ReadFile(filepath.Join(other, sshgrant.CertificateFile))
	os.WriteFile(filepath.Join(dir, sshgrant.CertificateFile), raw, 0600)
	if _, err := p.Acquire(ctx, nil); err == nil || err.Error() != "the certificate of claude-test is not for its key"+ask {
		t.Fatal(err)
	}
	// So is a key others can read.
	os.Chmod(filepath.Join(dir, sshgrant.KeyFile), 0644)
	if _, err := p.Acquire(ctx, nil); err == nil {
		t.Fatal("acquired a key others can read")
	}
	os.Remove(filepath.Join(dir, sshgrant.CertificateFile))
	os.Chmod(filepath.Join(dir, sshgrant.KeyFile), 0600)
	if _, err := p.Acquire(ctx, nil); err == nil || err.Error() != "claude-test has no certificate yet"+ask {
		t.Fatal(err)
	}
	if err := p.Revoke(ctx, ledger.Entry{Provider: "ssh", Name: "claude-test"}); !errors.Is(err, ledger.ErrGone) || !exists(filepath.Join(dir, sshgrant.KeyFile)) {
		t.Fatalf("revoked a pinned agent: %v", err)
	}
}

// watchAsync runs Watch in the background.
func watchAsync(p *Provider, ctx context.Context, held provider.Credential) chan result {
	answer := make(chan result, 1)
	go func() {
		c, err := p.Watch(ctx, held)
		answer <- result{c, err}
	}()
	return answer
}

type result struct {
	c   provider.Credential
	err error
}

func await(t *testing.T, answer chan result) result {
	t.Helper()
	select {
	case r := <-answer:
		return r
	case <-time.After(10 * time.Second):
		t.Fatal("Watch did not answer")
	}
	return result{}
}

// Watch picks up a grant made while the session runs, then a new grant,
// and reports a certificate that was dropped or expired.
func TestWatch(t *testing.T) {
	p, dir := agent(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Nothing yet: Watch waits, and a failed load is no answer.
	answer := watchAsync(p, ctx, provider.Credential{})
	time.Sleep(50 * time.Millisecond)
	select {
	case r := <-answer:
		t.Fatalf("answered without a certificate: %+v", r)
	default:
	}
	testutil.SSHCertificate(t, dir, "-5m:+2h", "host:transcoder")
	first := await(t, answer)
	if first.err != nil || len(first.c.Files) != 2 {
		t.Fatalf("%+v", first)
	}
	// The same certificate is no answer either; a new grant is.
	answer = watchAsync(p, ctx, first.c)
	time.Sleep(50 * time.Millisecond)
	select {
	case r := <-answer:
		t.Fatalf("answered with the same certificate: %+v", r)
	default:
	}
	testutil.SSHCertificate(t, dir, "-5m:+4h", "host:transcoder", "host:mac-lab")
	second := await(t, answer)
	if second.err != nil || string(second.c.Files["ssh/id_ed25519-cert.pub"]) == string(first.c.Files["ssh/id_ed25519-cert.pub"]) {
		t.Fatalf("%+v", second)
	}
	// geas ssh drop, while the session holds the certificate.
	answer = watchAsync(p, ctx, second.c)
	for _, name := range []string{sshgrant.KeyFile, sshgrant.PublicKeyFile, sshgrant.CertificateFile} {
		os.Remove(filepath.Join(dir, name))
	}
	if r := await(t, answer); r.err == nil || r.err.Error() != "claude-test has no key yet: ask the human: geas ssh grant claude-test <host>" {
		t.Fatalf("%+v", r)
	}
	// The held certificate expiring is an answer of its own.
	p.now = func() time.Time { return second.c.Expires }
	if r := await(t, watchAsync(p, ctx, second.c)); r.err == nil || !strings.HasPrefix(r.err.Error(), "the certificate of claude-test expired at ") {
		t.Fatalf("%+v", r)
	}
	// And the session's end.
	answer = watchAsync(p, ctx, provider.Credential{})
	cancel()
	if r := await(t, answer); !errors.Is(r.err, context.Canceled) {
		t.Fatalf("%+v", r)
	}
}

func TestRenderer(t *testing.T) {
	dir := testutil.SessionDir(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := (Renderer{}).Render(dir, map[string]provider.Credential{"ssh": {}}); err != nil {
		t.Fatal(err)
	}
	raw, err := dir.ReadFile("ssh/config")
	if err != nil {
		t.Fatal(err)
	}
	generic := strings.ReplaceAll(strings.ReplaceAll(string(raw), dir.Path(), "$GEAS_SESSION_DIR"), home, "$HOME")
	testutil.Golden(t, filepath.Join("testdata", "config"), []byte(generic))
	// ssh reads it as written.
	if ssh, err := exec.LookPath("ssh"); err == nil {
		out, err := exec.Command(ssh, "-G", "-F", filepath.Join(dir.Path(), "ssh", "config"), "transcoder").Output()
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{
			"user agent\n",
			"identityfile " + filepath.Join(dir.Path(), "ssh", "id_ed25519") + "\n",
			"certificatefile " + filepath.Join(dir.Path(), "ssh", "id_ed25519-cert.pub") + "\n",
			"identitiesonly yes\n",
			"identityagent none\n",
			"batchmode yes\n",
			"userknownhostsfile " + filepath.Join(home, ".ssh", "known_hosts") + "\n",
		} {
			if !strings.Contains(string(out), want) {
				t.Errorf("ssh -G lacks %q:\n%s", want, out)
			}
		}
	}
	for _, bad := range []map[string]provider.Credential{
		{"gitlab:gitlab.com": {}},
		{"ssh": {}, "ssh:other": {}},
	} {
		if err := (Renderer{}).Render(dir, bad); err == nil {
			t.Errorf("rendered %v", bad)
		}
	}
	// Nothing left to hand over: the configuration goes.
	if err := (Renderer{}).Render(dir, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := dir.ReadFile("ssh/config"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ssh/config left: %v", err)
	}
	if got, err := quote("/a b/%d"); err != nil || got != `"/a b/%%d"` {
		t.Fatal(got, err)
	}
	if _, err := quote("/a\"b"); err == nil {
		t.Fatal("quoted a double quote")
	}
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// session is a new session's ledger, under the state directory the test
// set, and the provider of an opencode agent in work, the directory the
// test is in.
func session(t *testing.T, work string) (*Provider, *ledger.Ledger) {
	t.Helper()
	id, err := sessiondir.NewID(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dir, err := sessiondir.Create(id)
	if err != nil {
		t.Fatal(err)
	}
	book, err := ledger.Create(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { book.Close() })
	t.Setenv("AGENT_SSH_NAME", "")
	// New reads the working directory; testing.T.Chdir needs Go 1.24.
	previous, err := os.Getwd()
	if err != nil || os.Chdir(work) != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(previous) })
	p, err := New([]string{"/usr/local/bin/opencode", "--continue"})
	if err != nil {
		t.Fatal(err)
	}
	return p, book
}

// checkout is a new state directory, and a directory to start sessions in.
func checkout(t *testing.T) string {
	t.Helper()
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	work := filepath.Join(t.TempDir(), "geas-session-names")
	if err := os.Mkdir(work, 0700); err != nil {
		t.Fatal(err)
	}
	// As os.Getwd reports it, through any symlink in the temporary path.
	work, err := filepath.EvalSymlinks(work)
	if err != nil {
		t.Fatal(err)
	}
	return work
}

// Each session reserves a name of its own, which Revoke removes with the
// session's copies, for that session only.
func TestReserve(t *testing.T) {
	work := checkout(t)
	p, book := session(t, work)
	drawn := p.Name
	if err := p.Reserve(book); err != nil || p.Name != drawn || !strings.HasPrefix(p.Name, "opencode-geas-session-names-") || p.Setup().Env["AGENT_SSH_NAME"] != p.Name {
		t.Fatalf("%q %v", p.Name, err)
	}
	owner, err := sshgrant.ReadOwner(p.Name)
	if err != nil || owner != (sshgrant.Owner{Session: book.ID(), Tool: "opencode", Dir: work}) {
		t.Fatalf("%+v %v", owner, err)
	}
	entries, err := book.Entries()
	if err != nil || len(entries) != 1 || entries[0].Provider != "ssh" || entries[0].Name != p.Name || entries[0].Revoked {
		t.Fatalf("%+v %v", entries, err)
	}
	// Sessions of the same tool, in the same directory, get names of
	// their own.
	names := map[string]bool{p.Name: true}
	var others []*Provider
	var otherBooks []*ledger.Ledger
	for range 10 {
		other, otherBook := session(t, work)
		if err = other.Reserve(otherBook); err != nil || names[other.Name] {
			t.Fatalf("%q %v", other.Name, err)
		}
		names[other.Name] = true
		others, otherBooks = append(others, other), append(otherBooks, otherBook)
	}

	// The grant arrives, and the session holds its copies.
	dir, _ := sshgrant.AgentDir(p.Name)
	testutil.SSHCertificate(t, dir, "-5m:+2h", "host:transcoder")
	c, err := p.Acquire(context.Background(), book)
	if err != nil {
		t.Fatal(err)
	}
	copies, err := sessiondir.Open(book.ID())
	if err != nil {
		t.Fatal(err)
	}
	for rel, raw := range c.Files {
		copies.WriteFile(rel, raw)
	}
	if err = (Renderer{}).Render(copies, map[string]provider.Credential{ID: c}); err != nil {
		t.Fatal(err)
	}
	// Another session cannot remove it; this one can, and does.
	if err = others[0].Revoke(context.Background(), entries[0]); !errors.Is(err, ledger.ErrGone) || !exists(filepath.Join(dir, sshgrant.KeyFile)) {
		t.Fatal(err)
	}
	if err = p.Revoke(context.Background(), entries[0]); err != nil || exists(dir) {
		t.Fatal(err)
	}
	for _, rel := range []string{sshgrant.SessionKey, sshgrant.SessionCertificate, sshgrant.SessionConfig} {
		if _, err = copies.ReadFile(rel); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left: %v", rel, err)
		}
	}
	// As does the reaper, with nothing but the session's ID, and again.
	otherEntries, _ := otherBooks[0].Entries()
	revoker := NewRevoker(otherBooks[0].ID())
	if err = revoker.Revoke(context.Background(), otherEntries[0]); err != nil {
		t.Fatal(err)
	}
	if err = revoker.Revoke(context.Background(), otherEntries[0]); !errors.Is(err, ledger.ErrGone) {
		t.Fatal(err)
	}
	if other, _ := sshgrant.AgentDir(others[0].Name); exists(other) {
		t.Fatal("the reaper left the agent's directory")
	}
}

// A name that is taken is closed in the ledger, never removed, and
// replaced by a new one.
func TestReserveCollision(t *testing.T) {
	p, book := session(t, checkout(t))
	taken := p.Name
	dir, _ := sshgrant.AgentDir(taken)
	testutil.SSHCertificate(t, dir, "-5m:+2h", "host:transcoder")
	if err := p.Reserve(book); err != nil || p.Name == taken || !strings.HasPrefix(p.Name, "opencode-geas-session-names-") {
		t.Fatalf("%q %v", p.Name, err)
	}
	open, err := book.Unrevoked()
	if err != nil || len(open) != 1 || open[0].Name != p.Name {
		t.Fatalf("%+v %v", open, err)
	}
	all, _ := book.Entries()
	if len(all) != 2 || all[0].Name != taken || !all[0].Revoked {
		t.Fatalf("%+v", all)
	}
	// Even an entry that names the agent that held the name leaves it.
	if err = p.Revoke(context.Background(), all[0]); !errors.Is(err, ledger.ErrGone) || !exists(filepath.Join(dir, sshgrant.KeyFile)) {
		t.Fatal(err)
	}
}

// A session that cannot reserve a name starts without one.
func TestReserveFails(t *testing.T) {
	p, book := session(t, checkout(t))
	agents, _ := sshgrant.AgentsDir()
	if err := os.WriteFile(agents, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := p.Reserve(book); err == nil || p.Name != "" || len(p.Setup().Env) != 0 {
		t.Fatalf("%q %v", p.Name, err)
	}
	// What it recorded is closed by revoking it, and nothing else goes.
	open, _ := book.Unrevoked()
	results := book.Revoke(context.Background(), open, map[string]ledger.Revoker{ID: p})
	if len(results) != 1 || results[0].Err != nil && !errors.Is(results[0].Err, ledger.ErrGone) || !exists(agents) {
		t.Fatalf("%+v", results)
	}
}
