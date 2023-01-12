package auth

import (
	"oauth2/dto"
	"oauth2/repository"
	"oauth2/util"
)

type GrantType interface {
	GetClient() repository.Client
	GetIdentifier() string
	ValidateRequest() error
	SetClient(client repository.Client) GrantType
	CreateAccessToken(scopeRequested string) dto.AccessTokenResponse
}

// Client credentials

type ClientCredentialsGrantType struct {
	Client repository.Client
}

func (grantType ClientCredentialsGrantType) GetClient() repository.Client {
	return grantType.Client
}

func (grantType ClientCredentialsGrantType) GetIdentifier() string {
	return GrantTypeClientCredentials
}

func (grantType ClientCredentialsGrantType) ValidateRequest() error {
	return nil
}

func (grantType ClientCredentialsGrantType) CreateAccessToken(scopeRequested string) dto.AccessTokenResponse {

	accessTokenResponse := dto.AccessTokenResponse{
		ExpiresIn:   ExpirationTokenLifeTime,
		Type:        "bearer",
		AccessToken: util.GenerateToken(),
		Scope:       scopeRequested}
	repository.PersistAccessToken(
		accessTokenResponse.AccessToken,
		accessTokenResponse.Scope,
		grantType.GetClient(),
		ExpirationTokenLifeTime)

	return accessTokenResponse
}

func (grantType ClientCredentialsGrantType) SetClient(client repository.Client) GrantType {
	grantType.Client = client
	return grantType
}
