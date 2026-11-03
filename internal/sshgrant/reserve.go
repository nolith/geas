package sshgrant

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/nolith/geas/internal/secretfile"
	"github.com/nolith/geas/internal/sessiondir"
)

// OwnerFile, in an agent's directory, names the session that reserved the
// agent's name: that session removes the directory when it ends. A
// directory without one, such as a name the human pinned, is never removed
// but by geas ssh drop.
const OwnerFile = "session.json"

// Owner is the session that reserved an agent's name, and what helps the
// human tell its agent from the others.
type Owner struct {
	// Session is the session's ID, as its directory is named.
	Session string `json:"session"`
	// Tool is the harness's tool, the first part of the name.
	Tool string `json:"tool"`
	// Dir is the directory the session started in.
	Dir string `json:"dir"`
}

var (
	// ErrTaken is a Reserve of a name that has a directory already.
	ErrTaken = errors.New("the agent name is taken")
	// ErrNotOwned is a Release of a name its session did not reserve:
	// another session did, nobody did, or it is gone already.
	ErrNotOwned = errors.New("the agent name is not this session's")
)

// Reserve creates the directory of the agent name, owned by o.Session, or
// returns ErrTaken when name has one already. The directory appears whole,
// with its OwnerFile in it: a session that dies at any point leaves either
// nothing or a directory that names it.
func Reserve(name string, o Owner) error {
	dir, err := AgentDir(name)
	if err != nil {
		return err
	}
	agents := filepath.Dir(dir)
	if err = os.MkdirAll(agents, 0700); err != nil {
		return err
	}
	if err = os.Chmod(agents, 0700); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(agents, ".reserve-")
	if err != nil {
		return err
	}
	// Gone already once the rename succeeded.
	defer os.RemoveAll(staging)
	if err = secretfile.WriteJSON(filepath.Join(staging, OwnerFile), o); err != nil {
		return err
	}
	// rename(2) refuses a directory that has anything in it, so no other
	// agent's directory is ever replaced; it replaces an empty one, which
	// holds nothing to lose.
	err = os.Rename(staging, dir)
	if errors.Is(err, syscall.EEXIST) || errors.Is(err, syscall.ENOTEMPTY) || errors.Is(err, syscall.ENOTDIR) {
		return ErrTaken
	}
	if err != nil {
		return err
	}
	parent, err := os.Open(agents)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

// ReadOwner returns the session that reserved the agent name; an error
// wrapping os.ErrNotExist means none did.
func ReadOwner(name string) (Owner, error) {
	dir, err := AgentDir(name)
	if err != nil {
		return Owner{}, err
	}
	raw, err := secretfile.Read(filepath.Join(dir, OwnerFile))
	if err != nil {
		return Owner{}, err
	}
	var o Owner
	if err = json.Unmarshal(raw, &o); err != nil || o.Session == "" {
		return Owner{}, errors.New("unreadable owner of " + name)
	}
	return o, nil
}

// Ended reports whether o's session has ended: its directory is gone, or
// it never named one. A session that died without cleaning up, as at a
// power loss, leaves its directory, and has not ended by this measure.
func (o Owner) Ended() bool {
	path, err := sessiondir.Path(o.Session)
	if err != nil {
		return true
	}
	_, err = os.Lstat(path)
	return errors.Is(err, os.ErrNotExist)
}

// Release removes the directory of the agent name, its key and
// certificate, once session reserved it; otherwise it returns ErrNotOwned
// and removes nothing. The certificate goes first, and the OwnerFile last,
// so that a Release cut short can be done again.
func Release(name, session string) error {
	o, err := ReadOwner(name)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
		return ErrNotOwned
	}
	if err != nil {
		return err
	}
	if o.Session != session {
		return ErrNotOwned
	}
	dir, err := AgentDir(name)
	if err != nil {
		return err
	}
	for _, file := range []string{CertificateFile, KeyFile, PublicKeyFile} {
		if err = os.Remove(filepath.Join(dir, file)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	// Anything else in it, such as what a grant cut short left, goes too:
	// the directory is the session's. What a failed read misses, the final
	// Remove reports.
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if entry.Name() != OwnerFile {
			if err = os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
				return err
			}
		}
	}
	if err = os.Remove(filepath.Join(dir, OwnerFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Remove(dir)
}
