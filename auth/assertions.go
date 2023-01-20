package auth

import (
	"net/url"
	"oauth2/config"
	"oauth2/dto"
	"oauth2/error_handling"
	"oauth2/repository"
	"oauth2/util"
	"strings"
)

// TokenRequestAssertion Check /token request
func TokenRequestAssertion(request dto.TokenRequest) (GrantType, error) {

	if request.GrantType == "" {
		return nil, error_handling.ErrorHandler("invalid_request", "The grant type was not specified in the request", "")
	}
	grantType, err := getGrantType(request)
	if err != nil {
		return nil, error_handling.ErrorHandler("unsupported_grant_type", err.Error(), "")
	}
	if err := grantType.Assert(request); err != nil {
		return nil, err
	}
	return grantType, nil
}

// AuthorizeRequestAssertion Check /authorize request
func AuthorizeRequestAssertion(request dto.AuthorizeRequest) (ResponseType, error) {

	if request.ClientID == "" {
		return nil, error_handling.ErrorHandler("invalid_client", "No client id supplied", "")
	}
	client, err := repository.FindClientById(request.ClientID)
	if err != nil {
		return nil, error_handling.ErrorHandler("invalid_client", "The client id supplied is invalid", "")
	}

	if request.RedirectUri != "" {
		urlParsed, _ := url.Parse(request.RedirectUri)
		if urlParsed.Fragment != "" {
			return nil, error_handling.ErrorHandler("invalid_uri", "The redirect URI must not contain a fragment'", "")
		}
		if client.RedirectUri != "" && !assertRedirectUri(client.RedirectUri, request.RedirectUri) {
			return nil, error_handling.ErrorHandler("redirect_uri_mismatch", "The redirect URI provided is missing or does not match", "#section-3.1.2")
		}
	} else {

		if client.RedirectUri == "" {
			return nil, error_handling.ErrorHandler("invalid_uri", "No redirect URI was supplied or stored", "")
		}
		if len(strings.Split(client.RedirectUri, " ")) > 1 {
			return nil, error_handling.ErrorHandler("invalid_uri", "A redirect URI must be supplied when multiple redirect URIs are registered", "#section-3.1.2.3")
		}
		request.RedirectUri = client.RedirectUri
	}

	if request.ResponseType == "" || !assertResponseType(request.ResponseType) {
		return nil, error_handling.ErrorHandler("invalid_request", "Invalid or missing response type", "")
	}
	if request.ResponseType == config.ResponseTypeCode {
		if !assertClientGrantType(client, config.GrantTypeAuthorizationCode) {
			return nil, error_handling.ErrorHandler("unauthorized_client", "The grant type is unauthorized for this client_id", "")
		}
		if config.AuthorizationCodeEnforceRedirect && request.RedirectUri == "" {
			return nil, error_handling.ErrorHandler("redirect_uri_mismatch", "The redirect URI is mandatory and was not supplied", "")
		}
	} else {

		if !config.AllowImplicit {
			return nil, error_handling.ErrorHandler("unsupported_response_type", "implicit grant type not supported", "")
		}
		if !assertClientGrantType(client, config.GrantTypeImplicit) {
			return nil, error_handling.ErrorHandler("unauthorized_client", "The grant type is unauthorized for this client_id", "")
		}
	}

	request.Scope, err = assertScope(request.Scope, client.Scope)
	if err != nil {
		return nil, err
	}

	if config.EnforceState && request.State == "" {
		return nil, error_handling.ErrorHandler("invalid_request", "The state parameter is required", "")
	}
	return getResponseType(client, request)
}

// assertClient Check client credentials against DB
func assertClient(request dto.TokenRequest) (repository.Client, error) {

	var client repository.Client

	if !config.AllowCredentialsInRequestBody && request.ClientID != "" {
		return client, error_handling.ErrorHandler("invalid_request", "Client credentials must be included thought HTTP Basic authentication scheme", "")
	}
	if config.AllowCredentialsInRequestBody && request.ClientID == "" {
		request.ClientID, request.ClientSecret = util.DecodeHeaderCredentials(request.AuthorizationHeader)
	}
	if request.ClientID == "" {
		return client, error_handling.ErrorHandler("invalid_client", "No client id supplied", "")
	}
	client, err := repository.FindClientById(request.ClientID)
	if err != nil {
		return client, error_handling.ErrorHandler("invalid_client", "The client id supplied is invalid", "")
	}
	if (client.Secret != request.ClientSecret) && !config.AllowPublicClients {
		return client, error_handling.ErrorHandler("invalid_client", "The client credentials are invalid", "")
	}
	if !assertClientGrantType(client, request.GrantType) {
		return client, error_handling.ErrorHandler("unauthorized_client", "The grant type is unauthorized for this client_id", "")
	}
	return client, nil
}

// assertScope Compare the scopes of the request with the scopes of the client
func assertScope(requestedScope string, clientScope string) (string, error) {

	if requestedScope != "" {

		result, _ := util.CompareScopes(clientScope, requestedScope)

		if !result {
			return "", error_handling.ErrorHandler("invalid_scope", "The scope requested is invalid for this request", "")
		}

	} else if clientScope != "" {
		return clientScope, nil
	} else {
		scopeDefaultList, err := repository.FindDefaultScope()
		if err != nil {
			return "", error_handling.ErrorHandler("invalid_scope", "This application requires you specify a scope parameter", "")
		}
		return util.NormalizeScopeList(scopeDefaultList), nil
	}
	return requestedScope, nil
}

// assertResponseType Check that the response type is supported
func assertResponseType(responseTypeRequested string) bool {

	for _, allowed := range []string{config.ResponseTypeCode, config.ResponseTypeImplicit} {
		if responseTypeRequested == allowed {
			return true
		}
	}
	return false
}

// assertClientGrantType Check the grant type of the request is enabled for the client
func assertClientGrantType(client repository.Client, grantType string) bool {
	for _, grantTypeAllowed := range client.GrantType {
		if grantTypeAllowed.GrantType == grantType {
			return true
		}
	}
	return false
}

// Internal method for validating redirect URI supplied
// see http://tools.ietf.org/html/rfc6749#section-3.1.2
func assertRedirectUri(clientUri string, requestedUri string) bool {

	registeredUris := strings.Split(clientUri, " ")
	for _, registeredUri := range registeredUris {
		if config.RequireExactRedirectUri {
			if strings.Compare(registeredUri, requestedUri) == 0 {
				return true
			}
		} else {
			requestedUriSubstr := requestedUri[0:len(registeredUri)]
			if strings.Compare(requestedUriSubstr, registeredUri) == 0 {
				return true
			}
		}
	}
	return false
}
