package auth

import "oauth2/repository"

type GrantType interface {
	GetClient() repository.Client
	GetIdentifier() string
	ValidateRequest() error
	SetClient(client repository.Client) GrantType
	CreateAccessToken() (string, int32, string)
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

func (grantType ClientCredentialsGrantType) CreateAccessToken() (string, int32, string) {
	return "", ExpirationTokenLifeTime, ""
}

func (grantType ClientCredentialsGrantType) SetClient(client repository.Client) GrantType {
	grantType.Client = client
	return grantType
}
