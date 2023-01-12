package auth

import (
	"errors"
	"oauth2/config"
	"oauth2/dto"
	"oauth2/repository"
	"oauth2/util"
)

type GrantType interface {
	GetIdentifier() string
	ValidateRequest(request dto.TokenRequest) error
	CreateAccessToken(scopeRequested string) dto.AccessTokenResponse
}

type ClientCredentialsGrantType struct {
	Client repository.Client
}

func (grantType *ClientCredentialsGrantType) GetIdentifier() string {
	return config.GrantTypeClientCredentials
}
func (grantType *ClientCredentialsGrantType) ValidateRequest(request dto.TokenRequest) error {
	return nil
}
func (grantType *ClientCredentialsGrantType) CreateAccessToken(scopeRequested string) dto.AccessTokenResponse {

	accessTokenResponse := dto.AccessTokenResponse{
		ExpiresIn:   config.AccessTokenLifeTime,
		Type:        "bearer",
		AccessToken: util.GenerateToken(),
		Scope:       scopeRequested}
	repository.PersistAccessToken(
		accessTokenResponse.AccessToken,
		accessTokenResponse.Scope,
		grantType.Client,
		config.AccessTokenLifeTime)

	return accessTokenResponse
}

type PasswordGrantType struct {
	Client repository.Client
	User   repository.User
}

func (grantType *PasswordGrantType) GetIdentifier() string {
	return config.GrantTypePassword
}
func (grantType *PasswordGrantType) ValidateRequest(request dto.TokenRequest) error {
	if request.Username == "" || request.Password == "" {
		return errors.New("missing parameters: \"username\" and \"password\" required")
	}
	user, err := repository.FindUserByUsername(request.Username)
	if err != nil {
		return errors.New("invalid username and password combination")
	}
	if passwordVerification := util.PasswordVerify(user.Password, request.Password); passwordVerification == false {
		return errors.New("invalid username and password combination")
	}
	grantType.User = user
	return nil
}
func (grantType *PasswordGrantType) CreateAccessToken(scopeRequested string) dto.AccessTokenResponse {

	accessTokenResponse := dto.AccessTokenResponse{
		ExpiresIn:   config.AccessTokenLifeTime,
		Type:        "bearer",
		AccessToken: util.GenerateToken(),
		Scope:       scopeRequested}

	if config.IncludeRefreshToken {
		accessTokenResponse.RefreshToken = util.GenerateToken()
		repository.PersistRefreshToken(
			accessTokenResponse.RefreshToken,
			accessTokenResponse.Scope,
			grantType.Client,
			config.RefreshTokenLifeTime)
	}

	repository.PersistAccessTokenWithUser(
		accessTokenResponse.AccessToken,
		accessTokenResponse.Scope,
		grantType.Client,
		grantType.User,
		config.AccessTokenLifeTime)

	return accessTokenResponse
}

type AuthorizationCodeGrantType struct {
	Client            repository.Client
	AuthorizationCode repository.AuthorizationCode
}

func (grantType *AuthorizationCodeGrantType) GetIdentifier() string {
	return config.GrantTypeAuthorizationCode
}
func (grantType *AuthorizationCodeGrantType) ValidateRequest(request dto.TokenRequest) error {
	if request.Code == "" {
		return errors.New("missing parameter: \"code\" is required")
	}
	authorizationCode, err := repository.FindAuthorizationCode(request.Code)
	if err != nil {
		return errors.New("authorization code doesn't exist or is invalid for the client")
	}
	if authorizationCode.Client.ID != grantType.Client.ID {
		return errors.New("authorization code doesn't exist or is invalid for the client")
	}
	if request.RedirectUri == "" || request.RedirectUri != authorizationCode.RedirectUri {
		return errors.New("the redirect URI is missing or do not match")
	}
	if util.CheckDateIsExpired(&authorizationCode.Expires) {
		return errors.New("the authorization code has expired")
	}
	grantType.AuthorizationCode = authorizationCode
	return nil
}
func (grantType *AuthorizationCodeGrantType) CreateAccessToken(scopeRequested string) dto.AccessTokenResponse {

	accessTokenResponse := dto.AccessTokenResponse{
		ExpiresIn:   config.AccessTokenLifeTime,
		Type:        "bearer",
		AccessToken: util.GenerateToken(),
		Scope:       scopeRequested}

	if config.IncludeRefreshToken {
		accessTokenResponse.RefreshToken = util.GenerateToken()
		repository.PersistRefreshToken(
			accessTokenResponse.RefreshToken,
			accessTokenResponse.Scope,
			grantType.Client,
			config.RefreshTokenLifeTime)
	}

	repository.PersistAccessTokenWithUser(
		accessTokenResponse.AccessToken,
		accessTokenResponse.Scope,
		grantType.Client,
		grantType.AuthorizationCode.User,
		config.AccessTokenLifeTime)

	repository.ExpireAuthorizationCode(grantType.AuthorizationCode.Code)

	return accessTokenResponse
}

type RefreshTokenGrantType struct {
	Client       repository.Client
	RefreshToken repository.RefreshToken
}

func (grantType *RefreshTokenGrantType) GetIdentifier() string {
	return config.GrantTypeRefreshToken
}
func (grantType *RefreshTokenGrantType) ValidateRequest(request dto.TokenRequest) error {

	if request.RefreshToken == "" {
		return errors.New("missing parameter: \"refresh_token\" is required")
	}
	refreshToken, err := repository.FindRefreshToken(request.RefreshToken)
	if err != nil {
		return errors.New("invalid refresh token")
	}
	if config.RefreshTokenLifeTime != 0 {
		if util.CheckDateIsExpired(refreshToken.Expires) {
			return errors.New("refresh token has expired")
		}
	}
	grantType.RefreshToken = refreshToken
	return nil
}
func (grantType *RefreshTokenGrantType) CreateAccessToken(scopeRequested string) dto.AccessTokenResponse {

	accessTokenResponse := dto.AccessTokenResponse{
		ExpiresIn:   config.AccessTokenLifeTime,
		Type:        "bearer",
		AccessToken: util.GenerateToken(),
		Scope:       scopeRequested}

	if config.IncludeRefreshToken {
		accessTokenResponse.RefreshToken = util.GenerateToken()
		repository.PersistRefreshToken(
			accessTokenResponse.RefreshToken,
			accessTokenResponse.Scope,
			grantType.Client,
			config.RefreshTokenLifeTime)
	}

	repository.PersistAccessTokenWithUser(
		accessTokenResponse.AccessToken,
		accessTokenResponse.Scope,
		grantType.Client,
		grantType.RefreshToken.User,
		config.AccessTokenLifeTime)

	if config.ExpireRefreshTokenAutomaticallyAfterUse {
		repository.ExpireRefreshToken(grantType.RefreshToken.Token)
	}
	return accessTokenResponse
}

type JwtBearerGrantType struct {
	Client repository.Client
}

func (grantType *JwtBearerGrantType) GetIdentifier() string {
	return config.GrantTypeJwtBearer
}
func (grantType *JwtBearerGrantType) ValidateRequest(request dto.TokenRequest) error {

	if request.Assertion == "" {
		return errors.New("Missing parameters: \"assertion\" required")
	}

	return nil
}
func (grantType *JwtBearerGrantType) CreateAccessToken(scopeRequested string) dto.AccessTokenResponse {

	accessTokenResponse := dto.AccessTokenResponse{
		ExpiresIn:   config.AccessTokenLifeTime,
		Type:        "bearer",
		AccessToken: util.GenerateToken(),
		Scope:       scopeRequested}

	repository.PersistAccessToken(
		accessTokenResponse.AccessToken,
		accessTokenResponse.Scope,
		grantType.Client,
		config.AccessTokenLifeTime)

	return accessTokenResponse
}
