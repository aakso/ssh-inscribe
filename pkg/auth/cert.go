package auth

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func MakeCertificates(key ssh.PublicKey, actx *AuthContext, validBefore time.Time, maxPrincipalsPerCert int) []*ssh.Certificate {
	var kid strings.Builder
	kid.WriteString(fmt.Sprintf("subject=%q", actx.GetSubjectName()))
	if aid, ok := actx.GetAuthMeta()[MetaAuditID]; ok {
		kid.WriteString(fmt.Sprintf(" audit_id=%q", aid))
	}
	kid.WriteString(fmt.Sprintf(" via=%q", strings.Join(actx.GetAuthenticators(), ",")))

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
