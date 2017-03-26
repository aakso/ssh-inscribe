package authldap

type Config struct {
	Name                     string
	Realm                    string
	ServerURL                string `yaml:"serverURL"`
	Timeout                  int
	Insecure                 bool
	UserBindDN               string   `yaml:"userBindDN"`
	UserSearchBase           string   `yaml:"userSearchBase"`
	UserSearchFilter         string   `yaml:"userSearchFilter"`
	UserSearchGetAttributes  []string `yaml:"userSearchGetAttributes"`
	AddPrincipalsFromGroups  bool     `yaml:"addPrincipalsFromGroups"`
	GroupSearchBase          string   `yaml:"groupSearchBase"`
	GroupSearchFilter        string   `yaml:"groupSearchFilter"`
	GroupSearchGetAttributes []string `yaml:"groupSearchGetAttributes"`
	SubjectNameTemplate      string   `yaml:"subjectNameTemplate"`
	PrincipalTemplate        string   `yaml:"principalTemplate"`

	Principals      []string
	CriticalOptions map[string]string `yaml:"criticalOptions"`
	Extensions      map[string]string
}

var Defaults *Config = &Config{
	Name:                     DefaultName,
	Realm:                    DefaultRealm,
	ServerURL:                "ldaps://127.0.0.1:636",
	Timeout:                  5,
	Insecure:                 false,
	UserBindDN:               "cn={{.UserName}},dc=example,dc=com",
	UserSearchBase:           "dc=example,dc=com",
	UserSearchFilter:         "(&(objectClass=user)(sAMAccountName={{.UserName}}))",
	UserSearchGetAttributes:  []string{"cn", "displayName"},
	AddPrincipalsFromGroups:  true,
	GroupSearchBase:          "dc=example,dc=com",
	GroupSearchFilter:        "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.User.DN}}))",
	GroupSearchGetAttributes: []string{"cn"},
	SubjectNameTemplate:      "{{.User.displayName}}",
	PrincipalTemplate:        "{{.Group.cn}}",

	Principals:      []string{},
	CriticalOptions: map[string]string{},
	Extensions:      map[string]string{},
}
