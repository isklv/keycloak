package keycloak

type Config struct {
	AuthURL        string
	BackendAuthURL string
	ClientID       string
	Realm          string
	RedirectURL    string // OAUTH
	ClientSecret   string // confidential / client credentials
}

func (c Config) Issuer() string {
	return c.AuthURL + "/realms/" + c.Realm
}

func (c Config) IssuerBackend() string {
	return c.BackendAuthURL + "/realms/" + c.Realm
}

func (c Config) JWKSURL() string {
	return c.IssuerBackend() + "/protocol/openid-connect/certs"
}

func (c Config) TokenURL() string {
	return c.IssuerBackend() + "/protocol/openid-connect/token"
}
