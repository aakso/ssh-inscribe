# TODO

Follow-ups from the 2026 security review and maintenance pass. Items marked
**breaking** change behaviour for existing deployments and were deliberately
left out of the maintenance branch.

## Security

### Restrict CA key upload (breaking)

`POST /v1/ca` and `/v1/ca/response` accept any user with a completed login
whenever no signing key is loaded, e.g. after a restart. Whoever uploads
first decides the CA key (unless `certSigningKeyFingerprint` is set, which is
strongly recommended meanwhile).

Add a server setting such as `caAdmins` (subject names and/or principal
globs) and refuse uploads from anyone else. Decide whether an unset list
disables API upload (secure, breaking for `sshi ca add` users) or keeps the
current behaviour with a warning.

### Reject weak user keys and SHA-1 signatures (breaking)

The server signs any public key type and size the client sends, and clients
may request `signing_option=ssh-rsa` (SHA-1 signature). Reject DSA keys and
RSA keys below 2048 bits, and make `ssh-rsa` signatures opt-in through server
configuration. The current RSA 4096 CA key is not affected.

### Enforce safe principals for LDAP (breaking)

All released OpenSSH versions (up to 10.2) split certificate principals on
commas when matching an `authorized_keys` `principals="..."` option, so a
principal `"x,admins"` also matches `admins`. OIDC principals with commas or
control characters are now dropped; for other backends the server only logs
a warning at signing time, because directory group names with commas may be
in legitimate use with `AuthorizedPrincipalsFile` (exact match). Check the
logs for `principal contains a comma`, then enforce for all backends.

### LDAP: derive the username principal from the directory (breaking)

With `userNamePrincipal: true` (the default) the principal is the username as
typed by the user. Directories normalise names (case, UPN vs. sAMAccountName),
so the typed form can differ from the canonical one. Prefer a configurable
attribute of the found user entry, e.g. `sAMAccountName` or `uid`.

### Before rolling out OIDC

- **Authorization request forwarding.** Anyone can start a flow and send the
  resulting identity provider URL to a victim. If the victim logs in, the
  victim's identity completes the attacker's pending login (PKCE and nonce do
  not help, the attacker holds both). Fix before production use, e.g. with an
  RFC 8252 loopback redirect handled by `sshi` (the code never reaches a
  browser of another person), or a confirmation page that shows a code also
  printed by the CLI.
- **MFA chaining.** Chained logins (`--login a,b`) are not required to be the
  same person; principals are the union of all links. Decide whether the
  second factor must match the first identity (e.g. compare a claim with the
  LDAP entry).
- **Multiple servers.** Pending OIDC logins are kept in memory. Instances
  behind SRV records need a shared `tokenSigningKey` and the client must keep
  talking to the same instance (it does today).
- **Identity provider specifics.** `requireVerifiedEmail` defaults to true and
  only applies when the `email` claim is mapped. Providers that do not emit
  `email_verified` (e.g. Entra ID) should map a stable, non user-editable
  claim instead of turning the check off.

### Rate limiting

There is no rate limiting on `/v1/auth/*`: LDAP password guessing (and
directory account lockouts as a side effect) and flooding pending OIDC logins
(`maxPendingAuthAttempts`) are only bounded by the network. Add per-client
limits or document a reverse proxy setup.

### Smaller items

- The default agent socket of non-packaged builds is
  `$TMPDIR/ssh_inscribe_agent.sock`. Sockets planted by other users are now
  refused; moving the default to a private runtime directory would be cleaner
  (changes the default path).
- Certificates are valid from "now". Back-dating `ValidAfter` by a minute
  would tolerate host clock skew (behaviour change).
- The client prints server-provided strings (errors, key ids, principals) to
  the terminal without filtering control characters.
- Release workflow: snapshot builds for pull requests run with
  `contents: write`; split them into a read-only job.

## Packaging (breaking for custom paths)

- Offer stricter systemd sandboxing as a documented drop-in:
  `ProtectSystem=strict`, `ReadWritePaths=/var/lib/ssh-inscribe`,
  `ProtectHome=yes`, `PrivateTmp=yes`, `RestrictAddressFamilies=AF_UNIX
  AF_INET AF_INET6`. It breaks agent sockets or configuration outside the
  default paths, so it cannot be the default. `PrivateDevices=` and
  `ProtectClock=` imply a device allow-list; with a USB HSM add an explicit
  `DeviceAllow=` for the token (or use it through pcscd).
- New installs create `/etc/ssh-inscribe/server_config.yaml` as `0640
  root:sshi`. Existing installs keep their permissions (previously `0644`);
  tighten them by hand or in a future post-install script.

## Dependencies

- `github.com/gobwas/glob`: v1 is a rewrite of the matcher that filters
  certificate principals. Evaluate (differential tests against v0.2.3) before
  upgrading.
- `github.com/labstack/echo/v4` -> v5 when v4 support ends.
- `github.com/sirupsen/logrus` (maintenance mode) -> `log/slog`.
- Unmaintained but working: `mitchellh/copystructure` (archived),
  `skratchdot/open-golang`, `chzyer/readline`, `ScaleFT/sshkeys`.
- YAML v3 migration (PR #57) changes parsing semantics; needs care.

## Test coverage

A dedicated pass to broaden coverage is warranted (55 % of statements after
the maintenance pass). Gaps, roughly by risk:

- `internal/auth`: `AuthContext` chain semantics (principals, removal,
  option merging, validity) are only covered indirectly.
- `internal/server/signapi`: login chaining (`MaxAuthContextChainLength`),
  federated login redirects and the callback handler.
- `internal/keysigner`: the PKCS#11 tests skip unless `TEST_SMARTCARD_ID`
  and `TEST_SMARTCARD_PIN` are set; run them against SoftHSM in CI. Worker
  recovery logic.
- `internal/ui`: federated login polling, CA challenge flow, Windows agent
  workaround.
- `cmd/sshi`: flag and environment handling, `ignoreFlagsAfter`,
  `sshKnownHostnames`.
- `internal/config` and `internal/logging`: section merging, package
  levels, syslog URL parsing.
- Fuzz tests: LDAP filter escaping, principal filter globs, certificate
  parsing on the client.
