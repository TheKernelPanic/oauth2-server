package repository

import (
	"errors"
	"time"
)

func PersistAccessToken(token string, scope string, client Client, expiresIn int32) {

	databaseConnection.Model(&AccessToken{}).Create(&AccessToken{
		Client:  client,
		Scope:   scope,
		Token:   token,
		Expires: time.Now().Add(time.Duration(expiresIn) * time.Second),
	})
}

func PersistAccessTokenWithUser(token string, scope string, client Client, user User, expiresIn int32) {

	databaseConnection.Model(&AccessToken{}).Create(&AccessToken{
		Client:  client,
		Scope:   scope,
		User:    user,
		Token:   token,
		Expires: time.Now().Add(time.Duration(expiresIn) * time.Second),
	})
}

func PersistRefreshToken(token string, scope string, client Client, expiresIn int32) {

	refreshToken := RefreshToken{
		Client: client,
		Scope:  scope,
		Token:  token}

	if expiresIn != 0 {

		expires := time.Now().Add(time.Duration(expiresIn) * time.Second)

		refreshToken.Expires = &expires
	}
	databaseConnection.Model(&RefreshToken{}).Create(&refreshToken)
}

func FindRefreshToken(token string) (RefreshToken, error) {

	var refreshToken RefreshToken

	databaseConnection.Model(&RefreshToken{}).Preload("Client").Preload("User").First(&refreshToken, "token = ?", token)

	if refreshToken.Token == "" {
		return refreshToken, errors.New("refresh token not found")
	}

	return refreshToken, nil
}

func ExpireRefreshToken(token string) {

	databaseConnection.Model(&RefreshToken{}).Where("token = ?", token).Update("expires", time.Now())
}
