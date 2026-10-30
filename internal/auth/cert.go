package auth

import (
	"fmt"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"
)

func MakeCertificates(key ssh.PublicKey, actx *AuthContext, validBefore time.Time, maxPrincipalsPerCert int) []*ssh.Certificate {
	var kid strings.Builder
	fmt.Fprintf(&kid, "subject=%q", actx.GetSubjectName())
	if aid, ok := actx.GetAuthMeta()[MetaAuditID]; ok {
		fmt.Fprintf(&kid, " audit_id=%q", aid)
	}
	fmt.Fprintf(&kid, " via=%q", strings.Join(actx.GetAuthenticators(), ","))

	remainingPrincipals := actx.GetPrincipals()
	if maxPrincipalsPerCert == 0 {
		maxPrincipalsPerCert = len(remainingPrincipals)
	}
	var certs []*ssh.Certificate
	for {
		pos := len(remainingPrincipals)
		if pos > maxPrincipalsPerCert {
			pos = maxPrincipalsPerCert
		}
		principals := remainingPrincipals[:pos]
		remainingPrincipals = remainingPrincipals[pos:]

		certs = append(certs, &ssh.Certificate{
			Key:             key,
			CertType:        ssh.UserCert,
			KeyId:           kid.String(),
			ValidPrincipals: principals,
			ValidAfter:      uint64(time.Now().Unix()),
			ValidBefore:     uint64(validBefore.Unix()),
			Permissions: ssh.Permissions{
				CriticalOptions: actx.GetCriticalOptions(),
				Extensions:      actx.GetExtensions(),
			},
		})
		if len(remainingPrincipals) == 0 {
			break
		}
	}
	return certs
}

// UnsafePrincipal reports whether p cannot be matched unambiguously by sshd.
// The authorized_keys principals="" option splits certificate principals on
// commas, so "a,b" matches both "a" and "b". Control characters are never
// legitimate.
func UnsafePrincipal(p string) bool {
	return p == "" || strings.ContainsFunc(p, func(r rune) bool {
		return r == ',' || unicode.IsControl(r)
	})
}
