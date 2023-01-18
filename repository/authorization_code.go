package repository

import (
	"errors"
	"time"
)

func PersistAuthorizationCode(code string, client Client, scope string, redirectUri string, expiresIn int32) {

	databaseConnection.Model(&AuthorizationCode{}).Omit("Client", "User").Create(&AuthorizationCode{
		ClientID:    client.ID,
		Scope:       scope,
		Code:        code,
		RedirectUri: redirectUri,
		Expires:     time.Now().Add(time.Duration(expiresIn) * time.Second),
	})
}

func FindAuthorizationCode(code string) (AuthorizationCode, error) {

	var authorizationCode AuthorizationCode

	databaseConnection.Model(&AuthorizationCode{}).Preload("Client").Preload("User").First(&authorizationCode, "code = ?", code)

	if authorizationCode.Code == "" {
		return authorizationCode, errors.New("authorization code not found")
	}

	return authorizationCode, nil
}

func ExpireAuthorizationCode(code string) {

	databaseConnection.Model(&AuthorizationCode{}).Where("code = ?", code).Update("expires", time.Now())
}
