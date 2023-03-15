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
	IdToken      string `json:"id_token,omitempty"`
}

type AuthorizeRequest struct {
	RedirectUri  string
	State        string
	ResponseType string
	Scope        string
	ClientID     string
	Nonce        string
	ResponseMode string // fragment (default), query, web_message, form_post
}

type TokenRequest struct {
	ClientID            string `form:"client_id"`
	Scope               string `form:"scope"`
	ClientSecret        string `form:"client_secret"`
	GrantType           string `form:"grant_type"`
	Username            string `form:"username"`
	Password            string `form:"password"`
	RedirectUri         string `form:"redirect_uri"`
	Code                string `form:"code"`
	State               string `form:"state"`
	RefreshToken        string `form:"refresh_token"`
	Assertion           string `form:"assertion"`
	AuthorizationHeader string
}

type JwtParams struct {
	jwt.RegisteredClaims
	Scope string `json:"scope,omitempty"`
}

type RevokeTokenRequest struct {
	TokenTypeHint string `form:"token_type_hint"`
	Token         string `form:"token"`
}

type IntrospectRequest struct {
	AccessToken string `form:"access_token"`
}

type IntrospectResponse struct {
	Realm     string
	TokenType string
}
