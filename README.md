# ssh-inscribe - SSH CA Client/Server
Note: this software is in alpha phase. Commands and API can change.
Feedback would be appreciated.

## Overview
ssh-inscribe can help you to manage your secure access to your
organizations SSH hosts. It achieves this by leveraging [SSH User
Certificates](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys).

Client/Server model allows us to store the CA key on a secure host
while users request certificates with the client. In addition the CA
key signing can also be offloaded to a HSM.

Users authenticate against the server using some credentials. After
the user is known we can generate a certificate with very specific
options and principals.

## Quick start (flat file authentication)
### Install and configure the server
1. Install the software, single binary `ssh-inscribe`
2. Generate default configuration file: `mkdir ~/.ssh_inscribe &&
   ssh-inscribe defaults > ~/.ssh_inscribe/config.yaml`
3. Edit `~/.ssh_inscribe/auth_users.yaml` example:
```
users:
- name: testuser
  # password hash. use "ssh-inscribe crypt" to generate
  password: $2a$10$75.sk/zr/Rg3SUVpkg2wy.6D6Y1PvBs73OUHJWVqoW5KsSeSxN0Be # test
  principals: 
  - testPrincipal
  criticalOptions: {}
  extensions:
    permit-pty: ""
    permit-user-rc: ""
    permit-agent-forwarding: ""
    permit-X11-forwarding: ""
```
4. Edit other options in `~/.ssh_inscribe/config.yaml` (you should set
   `TLSCertFile` and `TLSKeyFile` at least)
5. Start the server `ssh-inscribe server`
6. Use the client to add a CA signing key:
```
sshi --url <server url> ca add <keyfile>
```
alternatively you can use OpenSSH `ssh-add` command locally on the server:
```
SSH_AUTH_SOCK=<path to auth sock> ssh-add <keyfile>
```

## Use the client
Recommended way to use the client is to have `ssh-agent` running.
However keyfiles are also supported. Most options are also settable as
environmet variables. Check `sshi --help` and `sshi req --help` for up
to date list. 

You should at least set `SSH_INSCRIBE_URL` in your profile so you can
omit the --url flag.

### Quick start
The most simple way to use the client is to use the ssh subcommand.
This generates a temporary key and requests a certificate for it.
After this invokes the `ssh` command. All the flags and arguments are
passed thru. If `ssh-agent` is unavailable, an internal agent is
started for the duration of the session. Example:
```
# Assumes SSH_INSCRIBE_URL is set
sshi ssh <hostname> -l <username>
```

### Certificate request commands
#### Generate temporary key, request certificate for it and place it on the `ssh-agent`
```
sshi req --url <url to server> --generate
```
#### Request certificate for an existing key and place it on the `ssh-agent`
```
sshi req --url <url to server> --identity /path/to/identity/file
```
#### Request certificate for an existing key and write it to `<identity file>-cert.pub`
```
sshi req --url <url to server> --identity /path/to/identity/file --write
```
#### Generate temporary key, request certificate for it and write keys and cert to `<identity file>`
```
sshi req --url <url to server> --identity /path/to/identity/file --write --generate
```
You should now have three files:
* `/path/to/identity/file`
* `/path/to/identity/file.pub`
* `/path/to/identity/file-cert.pub`

#### Clear certificates and keys managed by `sshi` on the `ssh-agent`
```
sshi req --url <url to server> --clear
```

## Advanced topics
### LDAP
TODO

### HSM
TODO