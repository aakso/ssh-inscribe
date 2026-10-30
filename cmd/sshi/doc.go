// Command sshi is the ssh-inscribe client. It logs in to the server, requests
// a certificate for an existing or generated key and stores it in an ssh-agent
// or next to the identity file. "sshi ssh" and "sshi exec" run a command with
// the certificate made available through a filtering ad-hoc agent.
package main
