package auth

import (
	"oauth2/dto"
	"oauth2/error_handling"
	"oauth2/repository"
)

func RevokeToken(request dto.RevokeTokenRequest) error {

	if request.Token == "" {
		return error_handling.ErrorHandler("invalid_request", "Missing token parameter to revoke", "")
	}
	if request.TokenTypeHint == "access_token" {
		repository.ExpireAccessToken(request.Token)
	} else if request.TokenTypeHint == "refresh_token" {
		repository.ExpireRefreshToken(request.Token)
	} else {
		return error_handling.ErrorHandler("invalid_request", "Token type hint must be either 'access_token' or 'refresh_token'", "")
	}
	return nil
}
