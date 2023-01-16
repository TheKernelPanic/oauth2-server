package repository

import (
	"errors"
	"time"
)

func PersistAuthorizationCode(code string, client Client, scope string, expiresIn int32) {

	databaseConnection.Model(&AuthorizationCode{}).Create(&AuthorizationCode{
		Client:  client,
		Scope:   scope,
		Code:    code,
		Expires: time.Now().Add(time.Duration(expiresIn) * time.Second),
	})
}

func PersistAuthorizationCodeWithUser(code string, client Client, user User, scope string, expiresIn int32) {

	databaseConnection.Model(&AuthorizationCode{}).Create(&AuthorizationCode{
		Client:  client,
		Scope:   scope,
		Code:    code,
		User:    user,
		Expires: time.Now().Add(time.Duration(expiresIn) * time.Second),
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
