package objects

type DiscoverResult struct {
	AuthenticatorName           string `json:"authenticatorName"`
	AuthenticatorRealm          string `json:"authenticatorRealm"`
	AuthenticatorCredentialType string `json:"authenticatorCredentialType"`
	Default                     bool   `json:"default"`
}
