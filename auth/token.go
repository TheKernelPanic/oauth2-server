package auth

import (
	"oauth2/repository"
	"oauth2/util"
)

func CreateAccessToken(client repository.Client, scope string) (string, string, error) {

	accessToken := util.GenerateToken()

	// Mac, hmac-sha-1

	return accessToken, "bearer", nil
}
