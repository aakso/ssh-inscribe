package auth

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

func MakeCertificate(key ssh.PublicKey, actx *AuthContext) *ssh.Certificate {
	kid := []string{}
	kid = append(kid, fmt.Sprintf("subject=%q", actx.GetSubjectName()))
	if aid, ok := actx.GetAuthMeta()[MetaAuditID]; ok {
		kid = append(kid, fmt.Sprintf("audit_id=%q", aid))
	}
	kid = append(kid, fmt.Sprintf("via=%q", strings.Join(actx.GetAuthenticators(), ",")))
	return &ssh.Certificate{
		Key:             key,
		CertType:        ssh.UserCert,
		KeyId:           strings.Join(kid, " "),
		ValidPrincipals: actx.GetPrincipals(),
		Permissions: ssh.Permissions{
			CriticalOptions: actx.GetCriticalOptions(),
			Extensions:      actx.GetExtensions(),
		},
	}
}
