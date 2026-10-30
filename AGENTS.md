# AGENTS.md

Guidance for coding agents (and humans) working on ssh-inscribe.

## What this is

An SSH certificate authority. `ssh-inscribe` (server) authenticates users and
signs their SSH public keys with a CA key held by an `ssh-agent`, optionally
backed by a PKCS#11 HSM. `sshi` (client, also built for Windows) logs in,
requests certificates and stores them in an agent or next to an identity
file. It is used in production by several organisations; the LDAP and OIDC
backends matter most, `authfile` is for development and testing.

Treat it as security-critical software: a bug here can grant SSH access to
production hosts.

## Layout

```
cmd/ssh-inscribe        server CLI (server, defaults, crypt, version)
cmd/sshi                client CLI (req, ssh, exec, ca, version)
internal/server         HTTP server setup, timeouts, TLS, request logging
internal/server/signapi v1 API: /auth, /auth_callback, /sign, /ca, /ready
internal/auth           AuthContext chain, interfaces, certificate creation
internal/auth/backend/* authfile, authldap, authoidc (+ authmock for tests)
internal/auth/authz/*   principal glob filter
internal/keysigner      signing through ssh-agent, agent supervision, PKCS#11
internal/filteringagent agent proxy used by `sshi ssh/exec`
internal/ui             sshi client logic
internal/config         YAML config sections merged onto registered defaults
```

Every package has a `doc.go` describing it.

## Request flow

1. `GET /v1/auth` lists authenticators.
2. `POST /v1/auth/:name` with Basic auth (or nothing for federated backends)
   returns an HS256 JWT (120 s) that embeds the `AuthContext`. Sending a JWT
   in `X-Auth` chains logins (multi-factor); each link is a parent context.
   OIDC returns a *pending* context and a 303 with the identity provider URL;
   the client polls until the callback (`/v1/auth_callback/:name`) completed
   it.
3. `POST /v1/sign` with the JWT and a public key returns one or more
   certificates (principals are split with `max_principals_per_certificate`).
4. `/v1/ca` uploads the CA key when none is loaded (optionally through an
   encrypted challenge).

## Security invariants

Do not break these; each has a test.

- Never issue a certificate without principals (sshd may accept it for any
  user). Principals coming from an identity provider must not contain
  commas or control characters (`auth.UnsafePrincipal`).
- Every endpoint that acts on a login must require `AuthContext.IsValid()`
  (completed, not pending).
- Decode each JWT into a fresh claims object; only HS256 is accepted.
- Values from users or the directory are escaped before going into LDAP
  search filters (`filterContext`). Empty passwords are refused before any
  bind.
- OIDC: state is single-use and bound to a PKCE verifier and a nonce;
  `requireVerifiedEmail` guards email based principals.
- Do not connect to agent sockets another user could have planted
  (`util.CheckSocketPath`).
- Do not log secrets: passwords, private keys, authorization codes (the
  request logger redacts `code`), tokens.
- Use `crypto/rand` for anything security relevant (`util.Rand*`).

## Compatibility

The software is deployed; changes must not break existing usage unless
explicitly agreed.

- Configuration keys and their defaults (`ssh-inscribe defaults`) stay
  compatible. Config decoding matches keys case-insensitively, the
  `authfile` users file is parsed with yaml tags.
- The v1 HTTP API must keep working with older `sshi` clients and vice versa.
- `sshi` must build and work on Windows (`GOOS=windows`).
- Record intended breaking changes in `TODO.md` instead of making them.

## Working on the code

```
make check     # fmt-check, lint (linux + windows), test, govulncheck
make test      # needs ssh-agent in PATH (tests start real agents)
make lint      # golangci-lint, pinned version; includes govet
make fmt       # gofmt + gci import grouping
make test-ldap # authldap against OpenLDAP 2.4.57 and 389 DS (docker)
```

Known deployments use OpenLDAP 2.4, 389 Directory Server and Microsoft AD.
LDAP changes must pass `make test-ldap` and must not change behaviour for
existing directory configurations (AD cannot be tested in CI; keep
AD-specific behaviour such as the matching rule in groupSearchFilter working
by construction).

- Go version: see `go.mod` (`go` and `toolchain` lines). No vendoring.
- Lint has no exclusions. A `//nolint` must name the linter and give a
  reason, and is only acceptable when the flagged behaviour is intended
  (e.g. running the user's command). Fix everything else.
- Review automatic lint fixes: an `errorlint` autofix once inverted a
  condition in this code base.
- Errors: `fmt.Errorf("context: %w", err)`, `errors.Is/As`. Logging: the
  package level `Log` (logrus) with fields, never `fmt.Print` on the server.
- Imports are grouped: standard library, third party, this module.
- Tests use testify. Security fixes come with a test that fails without the
  fix. `authldap` tests do not run under `-race` (the mock directory server
  races); keep new LDAP tests that do not need it in files without the
  build tag.
- New dependencies: prefer the standard library; check maintenance status and
  known vulnerabilities (`make vuln`); avoid releases younger than a week.
- Commits follow Conventional Commits (`fix(authldap): ...`, `!` for
  breaking changes) and explain why.

See `TODO.md` for known open issues and planned work.
