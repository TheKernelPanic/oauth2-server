package auth

import (
	"errors"
	"fmt"
	"oauth2/config"
	"oauth2/dto"
	"oauth2/error_handling"
	"oauth2/repository"
)

func ClientAssertion(request dto.TokenRequest) (GrantType, error) {

	if request.ClientID == "" {
		return nil, error_handling.ErrorHandler("invalid_client", "", "No client id supplied")
	}
	if request.GrantType == "" {
		return nil, error_handling.ErrorHandler("invalid_request", "The grant type was not specified in the request", "")
	}
	client, err := repository.FindClientById(request.ClientID)
	if err != nil {
		return nil, error_handling.ErrorHandler("invalid_client", "", "The client id supplied is invalid")
	}
	if (client.Secret != request.ClientSecret) && !config.AllowPublicClients {
		return nil, error_handling.ErrorHandler("invalid_client", "The client credentials are invalid", "")
	}
	if !validateGrantType(client, request.GrantType) {
		return nil, error_handling.ErrorHandler("unauthorized_client", "The grant type is unauthorized for this client_id", "")
	}
	// TODO: Check scope
	grantType, err := getGrantType(client, request.GrantType)
	if err != nil {
		return nil, err
	}
	if err := grantType.ValidateRequest(request); err != nil {
		return nil, err
	}
	return grantType, nil
}

func getGrantType(client repository.Client, grantTypeRequested string) (GrantType, error) {

	if grantTypeRequested == config.GrantTypeClientCredentials {
		return &ClientCredentialsGrantType{Client: client}, nil
	}
	if grantTypeRequested == config.GrantTypePassword {
		return &PasswordGrantType{Client: client}, nil
	}
	if grantTypeRequested == config.GrantTypeAuthorizationCode {
		return &AuthorizationCodeGrantType{Client: client}, nil
	}
	if grantTypeRequested == config.GrantTypeRefreshToken {
		return &RefreshTokenGrantType{Client: client}, nil
	}
	return nil, errors.New(fmt.Sprintf("Grant type \"%s\" not supported", grantTypeRequested))
}

func AuthorizeAssertion(request dto.AuthorizeRequest) error {

	if request.ClientID == "" {
		return error_handling.ErrorHandler("invalid_client", "No client id supplied", "")
	}
	client, err := repository.FindClientById(request.ClientID)
	if err != nil {
		return error_handling.ErrorHandler("invalid_client", "The client id supplied is invalid", "")
	}

	if request.ResponseType == "" || !validateResponseType(request.ResponseType) {
		return error_handling.ErrorHandler("invalid_request", "Invalid or missing response type", "")
	}
	if !validateGrantType(client, config.GrantTypeAuthorizationCode) {
		return error_handling.ErrorHandler("unauthorized_client", "The grant type is unauthorized for this client_id", "")
	}

	// TODO: Redirect uri

	// TODO: Handle scopes

	if config.EnforceSate && request.State == "" {
		return error_handling.ErrorHandler("invalid_request", "The state parameter is required", "")
	}

	return nil
}

func validateResponseType(responseTypeRequested string) bool {

	if responseTypeRequested == config.ResponseTypeCode {
		return true
	}
	if responseTypeRequested == config.ResponseTypeImplicit {
		return config.AllowImplicit
	}
	return responseTypeRequested == config.ResponseTypeImplicit || responseTypeRequested == config.ResponseTypeCode
}

func validateGrantType(client repository.Client, grantType string) bool {
	for _, grantTypeAllowed := range client.GrantType {
		if grantTypeAllowed.GrantType == grantType {
			return true
		}
	}
	return false
}
