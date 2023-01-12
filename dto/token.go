package dto

import (
	"github.com/golang-jwt/jwt/v4"
)

type AccessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	Type         string `json:"token_type"`
	ExpiresIn    int32  `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type TokenRequest struct {
	ClientID     string `form:"client_id"`
	ClientSecret string `form:"client_secret"`
	GrantType    string `form:"grant_type"`
	Scope        string `form:"scope"`
	Username     string `form:"username"`
	Password     string `form:"password"`
	RedirectUri  string `form:"redirect_uri"`
	Code         string `form:"code"`
	State        string `form:"state"`
	RefreshToken string `form:"refresh_token"`
	Assertion    string `form:"assertion"`
}

type JwtParams struct {
	jwt.RegisteredClaims
	Scope string `json:"scope,omitempty"`
}
