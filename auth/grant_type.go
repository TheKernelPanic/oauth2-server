package auth

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"oauth2/config"
	"oauth2/dto"
	"oauth2/error_handling"
	"oauth2/repository"
	"oauth2/util"
)

func getGrantType(request dto.TokenRequest) (GrantType, error) {

	if request.GrantType == config.GrantTypeClientCredentials {
		return &ClientCredentialsGrantType{Request: request}, nil
	}
	if request.GrantType == config.GrantTypePassword {
		return &PasswordGrantType{Request: request}, nil
	}
	if request.GrantType == config.GrantTypeAuthorizationCode {
		return &AuthorizationCodeGrantType{Request: request}, nil
	}
	if request.GrantType == config.GrantTypeRefreshToken {
		return &RefreshTokenGrantType{Request: request}, nil
	}
	if request.GrantType == config.GrantTypeJwtBearer {
		return &JwtBearerGrantType{}, nil
	}
	return nil, errors.New(fmt.Sprintf("Grant type \"%s\" not supported", request.GrantType))
}

type GrantType interface {
	GetIdentifier() string
	Assert(request dto.TokenRequest) error
	GetAccessToken() dto.AccessTokenResponse
}

type ClientCredentialsGrantType struct {
	Client  repository.Client
	Request dto.TokenRequest
}

func (grantType *ClientCredentialsGrantType) GetIdentifier() string {
	return config.GrantTypeClientCredentials
}
func (grantType *ClientCredentialsGrantType) Assert(request dto.TokenRequest) error {

	client, err := assertClient(request)
	if err != nil {
		return err
	}
	grantType.Client = client
	request.Scope, err = assertScope(request.Scope, client.Scope)
	if err != nil {
		return err
	}
	return nil
}
func (grantType *ClientCredentialsGrantType) GetAccessToken() dto.AccessTokenResponse {

	accessTokenResponse := dto.AccessTokenResponse{
		ExpiresIn:   config.AccessTokenLifeTime,
		Type:        "bearer",
		AccessToken: util.GenerateToken(),
		Scope:       grantType.Request.Scope}
	repository.PersistAccessToken(
		accessTokenResponse.AccessToken,
		accessTokenResponse.Scope,
		grantType.Client,
		config.AccessTokenLifeTime)

	return accessTokenResponse
}

type PasswordGrantType struct {
	Client  repository.Client
	User    repository.User
	Request dto.TokenRequest
}

func (grantType *PasswordGrantType) GetIdentifier() string {
	return config.GrantTypePassword
}
func (grantType *PasswordGrantType) Assert(request dto.TokenRequest) error {

	client, err := assertClient(request)
	if err != nil {
		return err
	}
	grantType.Client = client
	request.Scope, err = assertScope(request.Scope, client.Scope)
	if err != nil {
		return err
	}
	if request.Username == "" || request.Password == "" {
		return error_handling.ErrorHandler("invalid_request", "Missing parameters: 'username' and 'password' required", "")
	}
	user, err := repository.FindUserByUsername(request.Username)
	if err != nil {
		return error_handling.ErrorHandler("invalid_grant", "Invalid username and password combination", "")
	}
	if passwordVerification := util.PasswordVerify(user.Password, request.Password); passwordVerification == false {
		return error_handling.ErrorHandler("invalid_grant", "Invalid username and password combination", "")
	}
	grantType.User = user
	return nil
}
func (grantType *PasswordGrantType) GetAccessToken() dto.AccessTokenResponse {

	accessTokenResponse := dto.AccessTokenResponse{
		ExpiresIn:   config.AccessTokenLifeTime,
		Type:        "bearer",
		AccessToken: util.GenerateToken(),
		Scope:       grantType.Request.Scope}

	if config.AlwaysIssueNewRefreshToken {
		accessTokenResponse.RefreshToken = util.GenerateToken()
		repository.PersistRefreshTokenWithUser(
			accessTokenResponse.RefreshToken,
			accessTokenResponse.Scope,
			grantType.Client,
			grantType.User,
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
	Request           dto.TokenRequest
}

func (grantType *AuthorizationCodeGrantType) GetIdentifier() string {
	return config.GrantTypeAuthorizationCode
}
func (grantType *AuthorizationCodeGrantType) Assert(request dto.TokenRequest) error {

	client, err := assertClient(request)
	if err != nil {
		return err
	}
	grantType.Client = client
	request.Scope, err = assertScope(request.Scope, client.Scope)
	if err != nil {
		return err
	}
	if request.Code == "" {
		return error_handling.ErrorHandler("invalid_grant", "Missing parameter: 'code' is required", "")
	}
	authorizationCode, err := repository.FindAuthorizationCode(request.Code)
	if err != nil {
		return error_handling.ErrorHandler("invalid_grant", "authorization code doesn't exist or is invalid for the client", "")
	}
	if authorizationCode.Client.ID != grantType.Client.ID {
		return error_handling.ErrorHandler("invalid_grant", "authorization code doesn't exist or is invalid for the client", "")
	}
	if request.RedirectUri == "" || request.RedirectUri != authorizationCode.RedirectUri {
		return error_handling.ErrorHandler("redirect_uri_mismatch", "The redirect URI is missing or do not match", "")
	}
	if util.CheckDateIsExpired(&authorizationCode.Expires) {
		return error_handling.ErrorHandler("invalid_grant", "The authorization code has expired", "")
	}
	grantType.AuthorizationCode = authorizationCode
	return nil
}
func (grantType *AuthorizationCodeGrantType) GetAccessToken() dto.AccessTokenResponse {

	accessTokenResponse := dto.AccessTokenResponse{
		ExpiresIn:   config.AccessTokenLifeTime,
		Type:        "bearer",
		AccessToken: util.GenerateToken(),
		Scope:       grantType.Request.Scope}

	repository.PersistAccessToken(
		accessTokenResponse.AccessToken,
		accessTokenResponse.Scope,
		grantType.Client,
		config.AccessTokenLifeTime)

	repository.ExpireAuthorizationCode(grantType.AuthorizationCode.Code)

	return accessTokenResponse
}

type RefreshTokenGrantType struct {
	Client       repository.Client
	RefreshToken repository.RefreshToken
	Request      dto.TokenRequest
}

func (grantType *RefreshTokenGrantType) GetIdentifier() string {
	return config.GrantTypeRefreshToken
}
func (grantType *RefreshTokenGrantType) Assert(request dto.TokenRequest) error {

	client, err := assertClient(request)
	if err != nil {
		return err
	}
	grantType.Client = client
	request.Scope, err = assertScope(request.Scope, client.Scope)
	if err != nil {
		return err
	}
	if request.RefreshToken == "" {
		return error_handling.ErrorHandler("invalid_grant", "Missing parameter: 'refresh_token' is required", "")
	}
	refreshToken, err := repository.FindRefreshToken(request.RefreshToken)
	if err != nil {
		return error_handling.ErrorHandler("invalid_grant", "Invalid refresh token", "")
	}
	if config.RefreshTokenLifeTime != 0 {
		if util.CheckDateIsExpired(refreshToken.Expires) {
			return error_handling.ErrorHandler("invalid_grant", "Refresh token has expired", "")
		}
	}
	grantType.RefreshToken = refreshToken
	return nil
}
func (grantType *RefreshTokenGrantType) GetAccessToken() dto.AccessTokenResponse {

	accessTokenResponse := dto.AccessTokenResponse{
		ExpiresIn:   config.AccessTokenLifeTime,
		Type:        "bearer",
		AccessToken: util.GenerateToken(),
		Scope:       grantType.Request.Scope}

	if config.AlwaysIssueNewRefreshToken {
		accessTokenResponse.RefreshToken = util.GenerateToken()
		if grantType.RefreshToken.User.Username != "" {
			repository.PersistRefreshTokenWithUser(
				accessTokenResponse.RefreshToken,
				accessTokenResponse.Scope,
				grantType.Client,
				grantType.RefreshToken.User,
				config.RefreshTokenLifeTime)
		} else {
			repository.PersistRefreshToken(
				accessTokenResponse.RefreshToken,
				accessTokenResponse.Scope,
				grantType.Client,
				config.RefreshTokenLifeTime)
		}
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
	Client  repository.Client
	User    repository.User
	Request dto.TokenRequest
}

func (grantType *JwtBearerGrantType) GetIdentifier() string {
	return config.GrantTypeJwtBearer
}
func (grantType *JwtBearerGrantType) Assert(request dto.TokenRequest) error {

	if request.Assertion == "" {
		return error_handling.ErrorHandler("invalid_request", "Missing parameters: 'assertion' required", "")
	}
	var err error
	grantType.Request = dto.TokenRequest{Scope: ""}

	jwtParsed, err := jwt.Parse(request.Assertion, func(token *jwt.Token) (interface{}, error) {

		claims := token.Claims.(jwt.MapClaims)

		// TODO: Handle algorithms
		// Only for RS256

		// issuer
		if claims["iss"] == nil {
			return nil, error_handling.ErrorHandler("invalid_grant", "Invalid issuer (iss) provided", "")
		}
		clientId := claims["iss"].(string)

		grantType.Client, err = repository.FindClientById(clientId)
		if err != nil {
			return nil, error_handling.ErrorHandler("invalid_grant", "Invalid issuer (iss) provided", "")
		}

		// subject
		if claims["sub"] == nil {
			return nil, error_handling.ErrorHandler("invalid_grant", "Invalid subject (sub) provided", "")
		}
		grantType.User, err = repository.FindUserByUsername(claims["sub"].(string))
		if err != nil {
			return nil, error_handling.ErrorHandler("invalid_grant", "Invalid subject (sub) provided", "")
		}

		// audience
		if claims["aud"] == nil || claims["aud"] != config.JwtAudienceUri {
			return nil, error_handling.ErrorHandler("invalid_grant", "Invalid audience (aud)", "")
		}

		if claims["scope"] != nil {
			grantType.Request.Scope = claims["scope"].(string)
		}

		// jti (nonce)
		if claims["jti"] != nil {

		}
		if len(grantType.Client.JwtConfig) != 1 {
			return nil, error_handling.ErrorHandler("invalid_grant", "JWT failed signature verification", "")
		}
		publicKey := grantType.Client.JwtConfig[0].PublicKey

		rsaPublicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))
		if err != nil {
			return nil, error_handling.ErrorHandler("invalid_grant", "JWT failed signature verification", "")
		}

		// TODO: Check sub, exp, nbf, aud, jti

		return rsaPublicKey, nil
	})
	if jwtParsed == nil {
		return error_handling.ErrorHandler("invalid_request", "JWT is malformed", "")
	}
	if err != nil {
		return error_handling.ErrorHandler("invalid_grant", err.(*jwt.ValidationError).Inner.Error(), "")
	}
	request.Scope, err = assertScope(request.Scope, grantType.Client.Scope)
	if err != nil {
		return err
	}

	return nil
}
func (grantType *JwtBearerGrantType) GetAccessToken() dto.AccessTokenResponse {

	accessTokenResponse := dto.AccessTokenResponse{
		ExpiresIn:   config.AccessTokenLifeTime,
		Type:        "bearer",
		AccessToken: util.GenerateToken(),
		Scope:       grantType.Request.Scope}

	if config.AlwaysIssueNewRefreshToken {
		accessTokenResponse.RefreshToken = util.GenerateToken()
		repository.PersistRefreshTokenWithUser(
			accessTokenResponse.RefreshToken,
			accessTokenResponse.Scope,
			grantType.Client,
			grantType.User,
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
