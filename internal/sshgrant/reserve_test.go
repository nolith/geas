package sshgrant

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nolith/geas/internal/testutil"
)

// Reserve hands a name to one session only, and Release removes it for that
// session only.
func TestReserveAndRelease(t *testing.T) {
	tool(t)
	owner := Owner{Session: "20261103T090000Z-0123456789abcdef", Tool: "opencode", Dir: "/src/geas"}
	if err := Reserve("opencode-geas-k3x9q2mz", owner); err != nil {
		t.Fatal(err)
	}
	dir, _ := AgentDir("opencode-geas-k3x9q2mz")
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("%v %v", info, err)
	}
	if got, err := ReadOwner("opencode-geas-k3x9q2mz"); err != nil || got != owner {
		t.Fatalf("%+v %v", got, err)
	}
	// Taken, whoever holds it, and left as it was.
	other := Owner{Session: "20261103T090001Z-fedcba9876543210", Tool: "opencode", Dir: "/src/geas"}
	if err := Reserve("opencode-geas-k3x9q2mz", other); !errors.Is(err, ErrTaken) {
		t.Fatal(err)
	}
	pinned, _ := AgentDir("claude-pinned")
	testutil.SSHCertificate(t, pinned, "-5m:+2h", "host:transcoder")
	if err := Reserve("claude-pinned", other); !errors.Is(err, ErrTaken) {
		t.Fatal(err)
	}
	if _, err := ReadOwner("claude-pinned"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reserved a pinned name: %v", err)
	}
	// Nothing of the reservations is left behind.
	entries, _ := os.ReadDir(filepath.Dir(dir))
	if len(entries) != 2 {
		t.Fatalf("agents' directory: %v", entries)
	}
	// Neither another session nor anyone releases what is not theirs.
	if err := Release("opencode-geas-k3x9q2mz", other.Session); !errors.Is(err, ErrNotOwned) || !exists(dir) {
		t.Fatal(err)
	}
	if err := Release("claude-pinned", other.Session); !errors.Is(err, ErrNotOwned) || !exists(filepath.Join(pinned, CertificateFile)) {
		t.Fatal(err)
	}
	if err := Release("claude-absent", other.Session); !errors.Is(err, ErrNotOwned) {
		t.Fatal(err)
	}
	// Its session does, with a key, a certificate and a grant cut short.
	testutil.SSHCertificate(t, dir, "-5m:+2h", "host:transcoder")
	os.Mkdir(filepath.Join(dir, ".sign-123"), 0700)
	if err := Release("opencode-geas-k3x9q2mz", owner.Session); err != nil || exists(dir) {
		t.Fatal(err)
	}
	if err := Release("opencode-geas-k3x9q2mz", owner.Session); !errors.Is(err, ErrNotOwned) {
		t.Fatal(err)
	}
	if err := Reserve("Bad Name", owner); err == nil {
		t.Fatal("reserved a bad name")
	}
}

// Of sessions racing for one name, exactly one gets it.
func TestReserveRace(t *testing.T) {
	tool(t)
	var wg sync.WaitGroup
	results := make([]error, 8)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = Reserve("pi-race", Owner{Session: "20261103T090000Z-000000000000000" + string(rune('0'+i)), Tool: "pi"})
		}()
	}
	wg.Wait()
	won := 0
	for _, err := range results {
		switch {
		case err == nil:
			won++
		case !errors.Is(err, ErrTaken):
			t.Fatal(err)
		}
	}
	if won != 1 {
		t.Fatalf("%d sessions got the name: %v", won, results)
	}
}

// geas ssh show lists reserved names, and drop keeps a running session's
// reservation but removes an ended one's.
func TestReservedNames(t *testing.T) {
	ssh, out, _ := tool(t)
	session := testutil.SessionDir(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	ctx := context.Background()
	running := Owner{Session: session.ID(), Tool: "opencode", Dir: filepath.Join(home, "src", "geas")}
	ended := Owner{Session: "20261103T090000Z-0123456789abcdef", Tool: "claude", Dir: "/srv/other"}
	if err := Reserve("opencode-geas-k3x9q2mz", running); err != nil {
		t.Fatal(err)
	}
	if err := Reserve("claude-other-7hd2mx0q", ended); err != nil {
		t.Fatal(err)
	}
	if code, err := ssh.Run(ctx, []string{"show"}); code != 0 || err != nil {
		t.Fatal(code, err)
	}
	want := "claude-other-7hd2mx0q   no key yet (ended session in /srv/other)\n" +
		"opencode-geas-k3x9q2mz  no key yet (session in ~/src/geas)\n"
	if out.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out, want)
	}
	dir, _ := AgentDir("opencode-geas-k3x9q2mz")
	testutil.SSHCertificate(t, dir, "-5m:+2h", "host:transcoder")
	c, _ := certificate(t, "opencode-geas-k3x9q2mz")
	out.Reset()
	ssh.Run(ctx, []string{"show"})
	if want := "opencode-geas-k3x9q2mz  until " + c.Expires().Format("2006-01-02 15:04 MST") + ": host:transcoder (session in ~/src/geas)\n"; !strings.HasSuffix(out.String(), want) {
		t.Fatalf("got:\n%s\nwant:\n%s", out, want)
	}

	// A running session keeps its name.
	out.Reset()
	if code, err := ssh.Run(ctx, []string{"drop", "opencode-geas-k3x9q2mz"}); code != 0 || err != nil || out.String() != "Dropped the key and certificate of opencode-geas-k3x9q2mz; its session removes the name when it ends.\n" {
		t.Fatal(code, err, out)
	}
	if _, err := ReadOwner("opencode-geas-k3x9q2mz"); err != nil || exists(filepath.Join(dir, KeyFile)) || exists(filepath.Join(dir, CertificateFile)) {
		t.Fatal(err)
	}
	if code, err := ssh.Run(ctx, []string{"drop", "opencode-geas-k3x9q2mz"}); code != 1 || err == nil || err.Error() != "opencode-geas-k3x9q2mz has no key to drop: its session removes the name when it ends" {
		t.Fatal(code, err)
	}
	// An ended one, as after a crash its reaper did not survive, does not.
	out.Reset()
	if code, err := ssh.Run(ctx, []string{"drop", "claude-other-7hd2mx0q"}); code != 0 || err != nil || out.String() != "Dropped claude-other-7hd2mx0q.\n" {
		t.Fatal(code, err, out)
	}
	if other, _ := AgentDir("claude-other-7hd2mx0q"); exists(other) {
		t.Fatal("the ended session's name is left")
	}
}
