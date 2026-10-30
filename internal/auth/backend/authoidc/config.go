package authoidc

type TokenValueMapping struct {
	SubjectNameField    string `yaml:"subjectNameField"`
	SubjectNameTemplate string `yaml:"subjectNameTemplate"`
	PrincipalsField     string `yaml:"principalsField"`
	PrincipalTemplate   string `yaml:"principalTemplate"`
}

type Config struct {
	Name  string
	Realm string

	Timeout                int      `yaml:"timeout"`
	ClientID               string   `yaml:"clientID"`
	ClientSecret           string   `yaml:"clientSecret"`
	Scopes                 []string `yaml:"scopes"`
	AuthFlowTimeout        int      `yaml:"authFlowTimeout"`
	MaxPendingAuthAttempts int      `yaml:"maxPendingAuthAttempts"`
	RedirectURL            string   `yaml:"redirectURL"`
	ProviderURL            string   `yaml:"providerURL"`

	ValueMappings TokenValueMapping `yaml:"valueMappings"`

	// RequireVerifiedEmail rejects logins where the email claim is mapped
	// to the subject name or principals but email_verified is not true.
	RequireVerifiedEmail bool `yaml:"requireVerifiedEmail"`

	Principals      []string
	CriticalOptions map[string]string `yaml:"criticalOptions"`
	Extensions      map[string]string
}

var Defaults = &Config{
	Name:                   DefaultName,
	Realm:                  DefaultRealm,
	Scopes:                 []string{"openid", "email", "profile"},
	AuthFlowTimeout:        240,
	MaxPendingAuthAttempts: 1000,
	RequireVerifiedEmail:   true,

	ValueMappings: TokenValueMapping{
		SubjectNameField:    "name",
		SubjectNameTemplate: "{{.}}",
		PrincipalsField:     "email",
		PrincipalTemplate:   "{{.}}",
	},

	Timeout: 15,
}
