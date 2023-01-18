package auth

import (
	"errors"
	"fmt"
	"oauth2/config"
	"oauth2/dto"
	"oauth2/repository"
	"oauth2/util"
)

func getResponseType(client repository.Client, currentRequest dto.AuthorizeRequest) (ResponseType, error) {
	if currentRequest.ResponseType == config.ResponseTypeCode {
		return &ResponseTypeCode{Client: client, CurrentRequest: currentRequest}, nil
	}
	if currentRequest.ResponseType == config.ResponseTypeImplicit {
		return &ResponseTypeImplicit{Client: client, CurrentRequest: currentRequest}, nil
	}
	return nil, errors.New(fmt.Sprintf("Response type \"%s\" not supported", currentRequest.ResponseType))
}

type ResponseType interface {
	GetUri() string
}

type ResponseTypeCode struct {
	User           repository.User
	Client         repository.Client
	CurrentRequest dto.AuthorizeRequest
}

type ResponseTypeImplicit struct {
	Client         repository.Client
	User           repository.User
	CurrentRequest dto.AuthorizeRequest
}

func (responseType *ResponseTypeCode) GetUri() string {

	code := util.GenerateAuthorizationCode()

	repository.PersistAuthorizationCode(
		code,
		responseType.Client,
		responseType.CurrentRequest.Scope,
		responseType.CurrentRequest.RedirectUri,
		config.AuthCodeLifeTime)

	return util.BuildUrlAuthorizationCode(
		responseType.CurrentRequest.RedirectUri,
		responseType.CurrentRequest.Scope,
		responseType.CurrentRequest.State,
		code)
}

func (responseType *ResponseTypeImplicit) GetUri() string {

	accessToken := util.GenerateToken()

	repository.PersistAccessToken(
		accessToken,
		responseType.CurrentRequest.Scope,
		responseType.Client,
		config.AccessTokenLifeTime)

	return util.BuildUrlAuthorizationImplicit(
		responseType.CurrentRequest.RedirectUri,
		responseType.CurrentRequest.Scope,
		responseType.CurrentRequest.State,
		accessToken)
}
