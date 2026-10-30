// Command ssh-inscribe runs the SSH certificate authority server. It
// authenticates users through the configured auth backends and signs their SSH
// public keys with a CA key held by an ssh-agent (optionally backed by a
// PKCS#11 token).
package main
