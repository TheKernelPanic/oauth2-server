package config

const (
	GrantTypeClientCredentials = "client_credentials"
	GrantTypePassword          = "password"
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypeJwtBearer         = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

const (
	AccessTokenLifeTime                     = 3600
	AllowPublicClients                      = false
	PasswordHashDefaultCost                 = 10
	RefreshTokenLifeTime                    = 0
	IncludeRefreshToken                     = true
	ExpireRefreshTokenAutomaticallyAfterUse = true
	AlwaysIssueNewRefreshToken              = true
)
