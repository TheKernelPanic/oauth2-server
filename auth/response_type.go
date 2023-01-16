package auth

import (
	"errors"
	"fmt"
	"oauth2/config"
	"oauth2/repository"
	"oauth2/util"
)

func getResponseType(client repository.Client, responseTypeRequested string) (ResponseType, error) {
	if responseTypeRequested == config.ResponseTypeCode {
		return &ResponseTypeCode{Client: client}, nil
	}
	if responseTypeRequested == config.ResponseTypeImplicit {
		return &ResponseTypeImplicit{Client: client}, nil
	}
	return nil, errors.New(fmt.Sprintf("Response type \"%s\" not supported", responseTypeRequested))
}

type ResponseType interface {
	GetUri() string
}

type ResponseTypeCode struct {
	User        repository.User
	Client      repository.Client
	State       string
	Scope       string
	RedirectUri string
}

type ResponseTypeImplicit struct {
	Client repository.Client
	State  string
	Scope  string
}

func (responseType *ResponseTypeCode) GetUri() string {

	code := util.GenerateAuthorizationCode()

	repository.PersistAuthorizationCode(code, responseType.Client, responseType.Scope, config.AuthCodeLifeTime)

	// TODO
	return ""
}

func (responseType *ResponseTypeImplicit) GetUri() string {

	accessToken := util.GenerateToken()

	repository.PersistAccessToken(
		accessToken,
		responseType.Scope,
		responseType.Client,
		config.AccessTokenLifeTime)

	return ""
}
