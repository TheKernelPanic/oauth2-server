package repository

import (
	"database/sql"
	"errors"
	"time"
)

func PersistAccessToken(token string, scope string, client Client, expiresIn int32) {

	databaseConnection.Model(&AccessToken{}).Omit("User", "Client").Create(&AccessToken{
		ClientID: client.ID,
		Scope:    scope,
		Token:    token,
		Expires:  time.Now().Add(time.Duration(expiresIn) * time.Second),
	})
}

func PersistAccessTokenWithUser(token string, scope string, client Client, user User, expiresIn int32) {

	databaseConnection.Model(&AccessToken{}).Omit("User", "Client").Create(&AccessToken{
		ClientID: client.ID,
		UserID:   sql.NullInt32{Valid: true, Int32: user.ID},
		Scope:    scope,
		Token:    token,
		Expires:  time.Now().Add(time.Duration(expiresIn) * time.Second),
	})
}

func ExpireAccessToken(token string) {

	databaseConnection.Model(&AccessToken{}).Where("token = ?", token).Update("expires", time.Now())
}

func PersistRefreshToken(token string, scope string, client Client, expiresIn int32) {

	refreshToken := RefreshToken{
		ClientID: client.ID,
		Scope:    scope,
		Token:    token}

	if expiresIn != 0 {

		expires := time.Now().Add(time.Duration(expiresIn) * time.Second)

		refreshToken.Expires = &expires
	}
	databaseConnection.Model(&RefreshToken{}).Omit("User", "Client").Create(&refreshToken)
}

func PersistRefreshTokenWithUser(token string, scope string, client Client, user User, expiresIn int32) {

	refreshToken := RefreshToken{
		ClientID: client.ID,
		UserID:   sql.NullInt32{Valid: true, Int32: user.ID},
		Scope:    scope,
		Token:    token}

	if expiresIn != 0 {

		expires := time.Now().Add(time.Duration(expiresIn) * time.Second)

		refreshToken.Expires = &expires
	}
	databaseConnection.Model(&RefreshToken{}).Omit("User", "Client").Create(&refreshToken)
}

// FindRefreshToken Find single row
//
// token (primary key)
func FindRefreshToken(token string) (RefreshToken, error) {

	var refreshToken RefreshToken

	databaseConnection.Model(&RefreshToken{}).Preload("Client").Preload("User").First(&refreshToken, "token = ?", token)

	if refreshToken.Token == "" {
		return refreshToken, errors.New("refresh token not found")
	}
	return refreshToken, nil
}

// ExpireRefreshToken Expire refresh token
//
// token (primary key)
func ExpireRefreshToken(token string) {

	databaseConnection.Model(&RefreshToken{}).Where("token = ?", token).Update("expires", time.Now())
}
