package config

const (
	// AllowPublicClients Allow authenticate client without secret
	AllowPublicClients = false

	// RequireExactRedirectUri The redirect uri must be identical to that of the client
	RequireExactRedirectUri = true

	// AllowCredentialsInRequestBody Allow set client id and secret in request body
	AllowCredentialsInRequestBody = true

	// AccessTokenLifeTime Access token lifetime (default 1 hour)
	AccessTokenLifeTime = 3600

	// RefreshTokenLifeTime Access token lifetime (default 1 day)
	RefreshTokenLifeTime = 86400

	// AlwaysIssueNewRefreshToken Create new refresh token when access token is requested
	AlwaysIssueNewRefreshToken = true

	// ExpireRefreshTokenAutomaticallyAfterUse Expire refresh token automatically after of each use
	ExpireRefreshTokenAutomaticallyAfterUse = true

	// RedirectStatusCode Http code for authorization redirection
	RedirectStatusCode = 302

	// AuthCodeLifeTime Lifetime of authorization code
	AuthCodeLifeTime = 30

	// AuthorizationCodeEnforceRedirect Make 'redirect_uri' as mandatory
	AuthorizationCodeEnforceRedirect = false

	// EnforceState Make 'state' on authorize request as mandatory
	EnforceState = false

	// AllowImplicit Allow 'implicit' response type
	AllowImplicit = true

	// JwtAudienceUri Audience uri of oauth server
	JwtAudienceUri = "http://localhost:3000"

	// PasswordHashDefaultCost For bcrypt algorithm
	PasswordHashDefaultCost = 10

	// RfcDocsRefUrl Rfc link for error references
	RfcDocsRefUrl = "https://www.rfc-editor.org/rfc/rfc6749"

	// DefaultRealm provided on "WWW-Authenticate" header
	DefaultRealm = "oAuth2-server"
)

// Grant type support
const (
	GrantTypeClientCredentials = "client_credentials"
	GrantTypePassword          = "password"
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypeImplicit          = "implicit"
	GrantTypeJwtBearer         = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

// Response type support
const (
	ResponseTypeCode     = "code"
	ResponseTypeImplicit = "implicit"
)
