# Development

The code layout and the rules that keep it in shape are in
[`AGENTS.md`](../AGENTS.md).

## Checks

```bash
nix develop          # Go, gopls, gh, glab, nixfmt, rumdl and treefmt

gofmt -l .           # must print nothing
go vet ./...
go test -race ./...

nix fmt              # gofmt, nixfmt and rumdl, through treefmt
treefmt              # the same, from treefmt.toml (inside nix develop)
nix flake check -L   # authoritative: formatting, vet, race tests, build
```

Markdown is linted and fixed by [rumdl](https://github.com/rvben/rumdl),
configured in [`.rumdl.toml`](../.rumdl.toml): prose wraps at 80 columns,
table columns stay aligned. `rumdl check .` lists what it cannot fix
itself.

Some launcher and reaper tests run `ps` to check process groups, so they
fail where `ps` cannot run, such as inside a sandbox; `nix flake check`
provides it. The `geas ssh` tests sign certificates with a real
`ssh-keygen`, which must be on `PATH`.

CI runs `nix flake check` with Go from nixpkgs-unstable: Radicle CI on
`x86_64-linux` (`.radicle/native.yaml`), and GitHub Actions on Linux and macOS.

## What the tests cover

Provider APIs are simulated; tests never use real credentials.

- **Configuration**: validation, path expansion, refusals, `config check`,
  `geas allowed`.
- **Identities and allowlists**: username checks, GitLab namespace
  resolution by model (group, your own namespace, project, another user's
  refused), scope building, namespace, owner and repository allowlists.
- **GitLab**: PAT creation and revocation, UTC expiry, the glab issuer
  through a fake `glab` (arguments, environment, locking, silent failures,
  a host per instance), one glab lock across hosts, two instances in one
  session, cancellable issuer input.
- **GitHub**: concurrent refresh, the refresh and its markers with a fake
  clock, cancellable locking, secret persistence.
- **Session directory**: modes, atomic writes, markers, the `Setup.Env`
  merge, each tool's configuration directory per override and per OS.
- **Renderers**: glab, gh, gitconfig, sandbox policy, nono and `ssh/config`
  against golden files, the last read back by `ssh -G`.
- **Git**: the credential helper with real Git, waiting for a slow issuer
  and failing fast with a failing one.
- **Lifecycle**: the harness starting before any provider step, a harness
  exiting during the mint, `geas status`, exit codes, process-group
  timeouts, revocation after SIGHUP with the output gone, the ledger, the
  reaper after SIGKILL (also during the mint, finding the PAT by name) and
  its silence after a clean exit, nested sessions, failing providers that
  never stop the start while Git refuses.
- **Sandbox**: the wrapper with its early-exit hint, the background sandbox
  check, `no_new_privs`.
- **`geas ssh`**: drawn and pinned agent names, `geas ssh name` inside
  and outside a session, reservations that one session of many wins and
  only their own session releases, durations and host names, the CA lists
  and the YubiKey picked by serial through a fake `ykman`, grants end to
  end with a software CA standing in for the YubiKey, `show` against
  `ssh-keygen -L`, the list with reserved names, `drop` of a running and
  an ended session's name, `enroll` with fakes, and the refusals without a
  terminal and inside a session.
- **The SSH provider**: expired, future, foreign and valid certificates,
  its watch picking up a grant, a re-grant and a drop, sessions in one
  directory drawing names of their own, a taken name replaced, a session
  whose harness gets a certificate granted while it runs, its agent
  removed at the end and by the reaper after SIGKILL, and pinned or
  inherited names, nested runs among them, left alone.

The golden files under `testdata/` follow what `glab` 1.123 and `gh` 2.102
write themselves; both read them back unchanged.
