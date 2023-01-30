package auth

import (
	"oauth2/dto"
	"oauth2/error_handling"
	"oauth2/repository"
	"oauth2/util"
	"time"
)

func Introspect(token string) (dto.AccessTokenResponse, error) {

	var response dto.AccessTokenResponse

	accessToken, err := repository.FindAccessToken(token)
	if err != nil {
		return response, error_handling.ErrorHandler("invalid_token", "The access token provided is invalid", "")
	}
	if util.CheckDateIsExpired(&accessToken.Expires) {
		return response, error_handling.ErrorHandler("invalid_token", "The access token provided has expired", "")
	}
	response.AccessToken = accessToken.Token
	response.Scope = accessToken.Scope
	response.ExpiresIn = int32(accessToken.Expires.Unix() - time.Now().Unix())
	// TODO: Persist token type into DB?¿
	response.Type = "Bearer"

	return response, nil
}
