# TODO

Follow-ups from the 2026 security review and maintenance pass. Items marked
**breaking** change behaviour for existing deployments and were deliberately
left out of the maintenance branch.

## Next release

Small client fixes to include in the next release. Both were found by
integration tests against OpenSSH 10.0 (Debian trixie) and affect 0.11.0 and
0.12.0.

### sshi ssh/exec: RSA keys fail through the filtering agent

With an ssh-agent running, `sshi ssh` and `sshi exec` serve keys through
`internal/filteringagent`. Its `Sign` ignores the signature algorithm ssh
asks for and picks the flags from the certificate's CA signature format
(`--signing-option`, default `rsa-sha2-256`). OpenSSH asks for
`rsa-sha2-512` first, gets an `rsa-sha2-256` signature back and gives up:
`sign_and_send_pubkey: no mutual signature supported`. RSA is the default
`--keytype`, so the default setup with an RSA CA is affected.

The user key's signature algorithm is unrelated to the CA's signature on the
certificate. Implement `agent.ExtendedAgent` and pass the requested flags
through (`SignWithFlags`); keep the current choice only for plain `Sign`
calls. Works today: `-o rsa-sha2-512`, `--agent-filter=false`, ed25519 keys,
or no ssh-agent (ad-hoc agent).

### sshi req: generated ed25519 key files are not loadable by OpenSSH

`sshi req -t ed25519 --generate --write` writes the private key as
openssh-key-v1 without padding the private section to the cipher block size
(8 for `none`); OpenSSH refuses it ("error in libcrypto"). The marshalling
comes from `ScaleFT/sshkeys` (`FormatOpenSSHv1`). Use
`ssh.MarshalPrivateKey` from `golang.org/x/crypto/ssh` for ed25519 keys
instead (it writes openssh-key-v1 for every key type; keep PEM for RSA unless
that change is wanted), here and for the CA key upload in `addCAKey`, and add
a test that loads the written key with `ssh-keygen -y`. RSA keys are written
as PEM and are not affected.

## Security

### Require caAdminPrincipals (breaking)

`caAdminPrincipals` limits CA key uploads (`POST /v1/ca`,
`/v1/ca/response`) to logins with a matching principal. When it is unset,
any completed login may still upload a key while none is loaded (a warning
is logged at startup unless `certSigningKeyFingerprint` is set). Consider
disabling API upload when the list is unset.

### Reject weak user keys and SHA-1 signatures (breaking)

The server signs any public key type and size the client sends, and clients
may request `signing_option=ssh-rsa` (SHA-1 signature). Reject DSA keys and
RSA keys below 2048 bits, and make `ssh-rsa` signatures opt-in through server
configuration. Check first which algorithms older network devices that trust
the CA support.

### LDAP: default for userNamePrincipalAttribute (breaking)

`userNamePrincipalAttribute` is empty by default, so the username principal
is still the name as typed. Consider a default (e.g. `sAMAccountName`, to go
with the AD oriented defaults) once deployments have set it explicitly.

### LDAP: check the AD domain in verifyBoundIdentity

AD answers WhoAmI with `u:DOMAIN\name`; only `name` is compared with the
`sAMAccountName` of the found entry. In a forest with several domains, a
UPN bind to `CHILD\alice` and a search that finds `ROOT\alice` pass the
check. Compare the domain too, e.g. with the constructed `msDS-PrincipalName`
attribute or the `crossRef` (`nETBIOSName`, `nCName`) of the domain; needs
a real AD to verify.

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

- authldap: any `startTLS` value in `serverURL` enables StartTLS, including
  `false` (a warning is logged).
- `util.CheckSocketPath` only inspects the socket's own directory and one
  symlink hop. Sockets owned by another user in a directory that user owns,
  or symlink chains through world-writable directories, are not detected.

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
- `make test-ldap` covers OpenLDAP 2.4.57 and 389 DS with an ACL that lets
  authenticated users read the directory; Microsoft AD (recursive group
  matching rule, UPN binds, the `u:DOMAIN\name` WhoAmI answer checked by
  `verifyBoundIdentity`) is not covered.
