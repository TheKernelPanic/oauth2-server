package auth

import (
	"oauth2/config"
	"oauth2/repository"
	"strings"
)

func validateResponseType(responseTypeRequested string) bool {

	for _, allowed := range []string{config.ResponseTypeCode, config.ResponseTypeImplicit} {
		if responseTypeRequested == allowed {
			return true
		}
	}
	return false
}

func validateGrantType(client repository.Client, grantType string) bool {
	for _, grantTypeAllowed := range client.GrantType {
		if grantTypeAllowed.GrantType == grantType {
			return true
		}
	}
	return false
}

// Internal method for validating redirect URI supplied
// see http://tools.ietf.org/html/rfc6749#section-3.1.2
func validateRedirectUri(clientUri string, requestedUri string) bool {

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
