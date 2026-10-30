// Package signapi implements the v1 HTTP API: login, certificate signing and
// CA key management. Login state is carried between requests in short-lived
// HS256 JWTs that embed the AuthContext.
package signapi
