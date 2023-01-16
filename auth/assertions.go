package auth

import (
	"net/url"
	"oauth2/config"
	"oauth2/dto"
	"oauth2/error_handling"
	"oauth2/repository"
	"strings"
)

func TokenRequestAssertion(request dto.TokenRequest) (GrantType, error) {

	if request.GrantType == "" {
		return nil, error_handling.ErrorHandler("invalid_request", "The grant type was not specified in the request", "")
	}
	if request.ClientID == "" {
		return nil, error_handling.ErrorHandler("invalid_client", "", "No client id supplied")
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

func AuthorizeRequestAssertion(request dto.AuthorizeRequest) (ResponseType, error) {

	if request.ClientID == "" {
		return nil, error_handling.ErrorHandler("invalid_client", "No client id supplied", "")
	}
	client, err := repository.FindClientById(request.ClientID)
	if err != nil {
		return nil, error_handling.ErrorHandler("invalid_client", "The client id supplied is invalid", "")
	}

	// Redirect URI
	var redirectUri string
	if request.RedirectUri != "" {
		urlParsed, _ := url.Parse(request.RedirectUri)
		if urlParsed.Fragment != "" {
			return nil, error_handling.ErrorHandler("invalid_uri", "The redirect URI must not contain a fragment'", "")
		}
		if client.RedirectUri != "" && !validateRedirectUri(client.RedirectUri, request.RedirectUri) {
			return nil, error_handling.ErrorHandler("redirect_uri_mismatch", "The redirect URI provided is missing or does not match", "#section-3.1.2")
		}
		redirectUri = request.RedirectUri
	} else {

		if client.RedirectUri == "" {
			return nil, error_handling.ErrorHandler("invalid_uri", "No redirect URI was supplied or stored", "")
		}
		if len(strings.Split(client.RedirectUri, " ")) > 1 {
			return nil, error_handling.ErrorHandler("invalid_uri", "A redirect URI must be supplied when multiple redirect URIs are registered", "#section-3.1.2.3")
		}
		redirectUri = client.RedirectUri
	}

	// Response Type
	if request.ResponseType == "" || !validateResponseType(request.ResponseType) {
		return nil, error_handling.ErrorHandler("invalid_request", "Invalid or missing response type", "")
	}
	if request.ResponseType == config.ResponseTypeCode {
		if !validateGrantType(client, config.GrantTypeAuthorizationCode) {
			return nil, error_handling.ErrorHandler("unauthorized_client", "The grant type is unauthorized for this client_id", "")
		}
		if config.AuthorizationCodeEnforceRedirect && redirectUri == "" {
			return nil, error_handling.ErrorHandler("redirect_uri_mismatch", "The redirect URI is mandatory and was not supplied", "")
		}
	} else {

		if !config.AllowImplicit {
			return nil, error_handling.ErrorHandler("unsupported_response_type", "implicit grant type not supported", "")
		}
		if !validateGrantType(client, config.GrantTypeImplicit) {
			return nil, error_handling.ErrorHandler("unauthorized_client", "The grant type is unauthorized for this client_id", "")
		}
	}

	// Scope TODO
	if request.Scope != "" {

	} else {

	}

	// State
	if config.EnforceState && request.State == "" {
		return nil, error_handling.ErrorHandler("invalid_request", "The state parameter is required", "")
	}

	return getResponseType(client, request.ResponseType)
}
