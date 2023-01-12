package dto

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	Type        string `json:"token_type"`
	ExpiresIn   int32  `json:"expires_in"`
	Scope       string `json:"scope"`
}
