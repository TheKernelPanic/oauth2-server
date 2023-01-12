package repository

import (
	"time"
)

func PersistAccessToken(accessToken string, scope string, client Client, expiresIn int32) {

	currentTime := time.Now()

	databaseConnection.Model(AccessToken{}).Create(&AccessToken{
		Client:    client,
		Scope:     scope,
		Token:     accessToken,
		ExpiresIn: currentTime.Add(time.Duration(expiresIn) * time.Second),
	})
}
