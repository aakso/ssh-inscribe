# ssh-inscribe - SSH CA Client/Server
Note: this software is in alpha phase. Commands and API can change.
Feedback would be appreciated.
<!-- TOC -->

- [ssh-inscribe - SSH CA Client/Server](#ssh-inscribe---ssh-ca-clientserver)
    - [Overview](#overview)
    - [Requirements](#requirements)
    - [Development version installation](#development-version-installation)
    - [Quick start (flat file authentication)](#quick-start-flat-file-authentication)
        - [Install and configure the server](#install-and-configure-the-server)
    - [Configure your hosts to trust the CA public key](#configure-your-hosts-to-trust-the-ca-public-key)
    - [Use the client](#use-the-client)
        - [Quick start](#quick-start)
        - [Certificate request commands](#certificate-request-commands)
    - [Advanced topics](#advanced-topics)
        - [LDAP](#ldap)
        - [HSM](#hsm)

<!-- /TOC -->
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

## Requirements
For server you need:
- `ssh-agent` binary in PATH
- Some execution environment such as Systemd or Docker as the server does not support daemonization

For client you need:
- `ssh` binary in path to use the ssh subcommand
- `ssh-agent` running for convenient use

## Development version installation
```
go install github.com/aakso/ssh-inscribe/...@latest
```

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
## Configure your hosts to trust the CA public key
There are many guides to this available in the web but the easiest way
is to use the `authorized_keys` file. Just put following in it:
```
cert-authority,principals="testPrincipal" <your CA Public Key>
```
It is also possible to configure global trust in your `sshd_config`.
Refer to `sshd_options` man page and look for `TrustedUserCAKeys` and
`AuthorizedPrincipalsFile` options.

## Use the client
Recommended way to use the client is to have `ssh-agent` running.
However keyfiles are also supported. Most options are also settable as
environment variables. Check `sshi --help` and `sshi req --help` for up
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
Here is an example configuration of a Directory Server Integration
```
mycompanyldapconfig:
  name: my.company.example.com
  realm: My Company Ltd
  serverUrl: ldaps://ad.my.company.example.com:636          # Using LDAP over SSL
  timeout: 5                                                # Connect and search timeout
  insecure: false                                           # Disables certificate validation on LDAP bind
  userBindDN: '{{.UserName}}@my.company.example.com'        # Template for binding. This example is for Microsoft AD
  userSearchBase: dc=my,dc=company,dc=example,dc=com
  userSearchFilter: (&(objectClass=user)(sAMAccountName={{.UserName}})) # For Microsoft AD
  addPrincipalsFromGroups: true                             # Add matching groups as SSH Cert Principals
  groupSearchBase: dc=my,dc=company,dc=example,dc=com
  groupSearchFilter: (&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.User.DN}})) # Recursive group search
  subjectNameTemplate: '{{.User.displayName}}'              # How to display user name in KeyId in the SSH Cert
  principalTemplate: 'my.company.example.com-{{.Group.cn}}' # How to display group based Principals in the SSH Cert
  # Add these Cert options to every successful authentication
  principals: []
  criticalOptions: {}
  extensions:
    permit-pty: ""
    permit-user-rc: ""
    permit-agent-forwarding: ""
    permit-X11-forwarding: ""
server:
  listen: :8540
  TLSCertFile: server_cert.pem # x509 certificate for HTTPS
  TLSKeyFile: server_key.pem
  authBackends:
  - type: authldap
    config: mycompanyldapconfig # Refer authldap config section
  maxCertLifetime: 24h
  defaultCertLifetime: 1h
```
Now here is an example session using the above configuration (ssh-agent is running):
```
mylaptop:~ aakso$ export SSH_INSCRIBE_URL=https://localhost:8540
mylaptop:~ aakso$ sshi ssh devbox.my.company.example.com
Enter Username for "my.company.example.com" (My Company Ltd): aakso
Enter Password for "my.company.example.com" (My Company Ltd):
CERT DETAILS:
         Fingerprint: SHA256:KUJHQ00IzkEmhH10HO3E7rddgARypH1pJgRH0ODbOHs (49:76:13:e4:08:ba:69:96:78:7a:99:9f:96:8d:90:86)
      CA Fingerprint: SHA256:VNyotPgHDkgsjEH7MhaTQrYTGe9mgIeMZxm5pS6uap0 (94:47:ae:2e:95:87:23:e1:45:fb:af:f8:26:43:91:ee)
               KeyId: subject="Anton Aksola" audit_id="WzaCsfQtrW8gEVEqTODJMqQ6jHnbmIya" via="my.company.example.com"
          Valid from: 1970-01-01 02:00:00 +0200 EET
            Valid to: 2017-04-06 09:35:12 +0300 EEST (expires in 59m59.25427059s)
          Principals:
                      my.company.example.com-SEC_DEVELOPER
                      my.company.example.com-SEC_PRODUCTION_SYSTEM_X
    Critical Options:
          Extensions:
                      permit-X11-forwarding
                      permit-agent-forwarding
                      permit-pty
                      permit-user-rc
Last login: Thu Apr  5 04:55:10 2017 from somewhere.at.my.company.example.com
[aakso@devbox ~]$
```
By using `ssh-agent` subsequent login happens without user/pass prompt until the cert is expired:
```
mylaptop:~ aakso$ sshi ssh devbox.my.company.example.com
Last login: Thu Apr  6 05:35:15 2017 from somewhere.at.my.company.example.com
[aakso@devbox ~]$
```


### HSM
TODO