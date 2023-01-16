package config

const (
	GrantTypeClientCredentials = "client_credentials"
	GrantTypePassword          = "password"
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypeImplicit          = "implicit"
	GrantTypeJwtBearer         = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

const (
	ResponseTypeCode     = "code"
	ResponseTypeImplicit = "implicit"
)

const (
	AccessTokenLifeTime                     = 3600
	AllowPublicClients                      = false
	PasswordHashDefaultCost                 = 10
	RefreshTokenLifeTime                    = 0
	IncludeRefreshToken                     = true
	ExpireRefreshTokenAutomaticallyAfterUse = true
	AlwaysIssueNewRefreshToken              = true
	AllowImplicit                           = false
	RequireExactRedirectUri                 = true
	RedirectStatusCode                      = 302
	AuthCodeLifeTime                        = 30
	AuthorizationCodeEnforceRedirect        = false
	EnforceState                            = false
	RfcDocsRefUrl                           = "https://www.rfc-editor.org/rfc/rfc6749"
)
