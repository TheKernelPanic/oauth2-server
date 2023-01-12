package auth

import (
	"errors"
	"fmt"
	"oauth2/config"
	"oauth2/dto"
	"oauth2/repository"
)

func ClientAssertion(request dto.TokenRequest) (GrantType, error) {

	if request.ClientID == "" {
		return nil, errors.New("no clit id supplied")
	}
	client, err := repository.FindClientById(request.ClientID)
	if err != nil {
		return nil, errors.New("the client credentials are invalid")
	}
	if (client.Secret != request.ClientSecret) && !config.AllowPublicClients {
		return nil, errors.New("the client credentials are invalid")
	}
	found := false
	for _, grantTypeAllowed := range client.GrantType {
		if grantTypeAllowed.GrantType == request.GrantType {
			found = true
			break
		}
	}
	if found == false {
		return nil, errors.New("the grant type is unauthorized for this client_id")
	}
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
