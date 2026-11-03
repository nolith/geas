package sshgrant

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// The random part of a session's agent name: 8 characters of Crockford's
// base32, which leaves out i, l, o and u, so that the human can read the
// name off a screen and type it. 40 bits make a name that a later session
// draws again, while a certificate granted to the old one may still be
// valid, practically impossible; Reserve refuses one that is in use.
const (
	suffixAlphabet = "0123456789abcdefghjkmnpqrstvwxyz"
	suffixLength   = 8
)

// maxDirSlug is how long the part of the name from the session's directory
// may get: enough to recognise a checkout, short enough that the grant
// command fits on a line. geas ssh show prints the whole directory.
const maxDirSlug = 24

// NewName is a new name for an agent of tool that starts in dir:
// <tool>-<dir>-<random>, with dir's base name as a slug of at most
// maxDirSlug characters, cut at a dash where it can be, and left out when
// nothing of it is usable, such as for /. Every session draws its own;
// Reserve makes it the session's.
func NewName(tool, dir string) (string, error) {
	if !agentName.MatchString(tool) {
		return "", errors.New("bad tool name: " + tool)
	}
	random := make([]byte, suffixLength)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	for i, b := range random {
		// 256 is a multiple of 32: every character is as likely.
		random[i] = suffixAlphabet[int(b)%len(suffixAlphabet)]
	}
	parts := []string{tool}
	if base := Slug(filepath.Base(dir)); base != "" {
		if len(base) > maxDirSlug {
			// At a dash, when there is one, rather than in a word.
			cut := base[:maxDirSlug+1]
			if i := strings.LastIndexByte(cut, '-'); i > 0 {
				cut = cut[:i]
			}
			base = strings.TrimRight(cut[:min(len(cut), maxDirSlug)], "-")
		}
		parts = append(parts, base)
	}
	return strings.Join(append(parts, string(random)), "-"), nil
}

// Pinned is the name AGENT_SSH_NAME gives an agent of tool, as the human
// may set it before geas run, and as a session sets it for the harness and
// what it runs: empty when it names no agent of tool.
func Pinned(tool string) string {
	if name := Slug(os.Getenv("AGENT_SSH_NAME")); tool != "" && strings.HasPrefix(name, tool+"-") {
		return name
	}
	return ""
}

// Name is the SSH name of the agent tool runs as, which its session gave it
// as AGENT_SSH_NAME; without tool, AGENT_SSH_NAME itself. A session draws a
// new name when it starts, so outside one there is nothing to predict.
func Name(tool string) (string, error) {
	switch {
	case tool != "" && !agentName.MatchString(tool):
		return "", errors.New("bad tool name: " + tool)
	case tool != "":
		if name := Pinned(tool); name != "" {
			return name, nil
		}
		return "", errors.New("AGENT_SSH_NAME names no agent of " + tool + ": each session names its agent when it starts, " + tool + "-<directory>-<random>, and sets AGENT_SSH_NAME; geas ssh show lists the names sessions hold")
	}
	if name := Slug(os.Getenv("AGENT_SSH_NAME")); name != "" {
		return name, nil
	}
	return "", errors.New("no agent: give a <tool>, or run inside a geas session")
}
