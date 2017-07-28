package authoidc

type TokenValueMapping struct {
	SubjectNameField string `yaml:"subjectNameField"`
	PrincipalsField  string `yaml:"principalsField"`
}

type Config struct {
	Name  string
	Realm string

	Timeout                int      `yaml:"timeout"`
	ClientId               string   `yaml:"clientID"`
	ClientSecret           string   `yaml:"clientSecret"`
	Scopes                 []string `yaml:"scopes"`
	AuthFlowTimeout        int      `yaml:"authFlowTimeout"`
	MaxPendingAuthAttempts int      `yaml:"maxPendingAuthAttempts"`
	RedirectURL            string   `yaml:"redirectURL"`
	ProviderURL            string   `yaml:"providerURL"`

	ValueMappings TokenValueMapping `yaml:"valueMappings"`

	Principals      []string
	CriticalOptions map[string]string `yaml:"criticalOptions"`
	Extensions      map[string]string
}

var Defaults *Config = &Config{
	Name:                   DefaultName,
	Realm:                  DefaultRealm,
	Scopes:                 []string{"openid", "email", "profile"},
	AuthFlowTimeout:        240,
	MaxPendingAuthAttempts: 1000,

	ValueMappings: TokenValueMapping{
		SubjectNameField: "name",
		PrincipalsField:  "email",
	},

	Timeout: 15,
}
