package auth

import (
	"errors"
	"oauth2/repository"
)

func ClientAssertion(id string, secret string, grantTypeRequested string, scope string) (GrantType, error) {

	client, err := repository.FindClientById(id)
	if err != nil {

	}
	if (client.Secret != secret) && !AllowPublicClients {
		return nil, errors.New("invalid secret")
	}
	found := false
	for _, grantTypeAllowed := range client.GrantType {
		if grantTypeAllowed.GrantType == grantTypeRequested {
			found = true
			break
		}
	}
	if found == false {
		return nil, errors.New("invalid grant type")
	}
	return getGrantType(grantTypeRequested).SetClient(client), nil
}

func getGrantType(grantTypeRequested string) GrantType {

	if grantTypeRequested == GrantTypeClientCredentials {
		return ClientCredentialsGrantType{}
	}
	panic("Unsupported grant type")
}
