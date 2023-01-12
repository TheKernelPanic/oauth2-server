package http

import (
	"github.com/gofiber/fiber/v2"
	"oauth2/auth"
	"oauth2/util"
)

type TokenRequest struct {
	ClientID     string `form:"client_id"`
	ClientSecret string `form:"client_secret"`
	GrantType    string `form:"grant_type"`
	Scope        string `form:"scope"`
	Username     string `form:"username"`
	Password     string `form:"password"`
}

func TokenController(context *fiber.Ctx) error {

	var request TokenRequest

	if err := context.BodyParser(&request); err != nil {
		return err
	}

	if request.GrantType == "" {
		return context.Status(400).Send(nil)
	}
	authorizationHeader := context.Get("Authorization")
	if authorizationHeader != "" {
		request.ClientID, request.ClientSecret = util.DecodeHeaderCredentials(authorizationHeader)
	}
	grantType, err := auth.ClientAssertion(request.ClientID, request.ClientSecret, request.GrantType, request.Scope)
	if err != nil {
		return context.Status(401).SendString(err.Error())
	}

	//accessTokenResponse := AccessTokenResponse{
	//	ExpiresIn: auth.ExpirationTokenLifeTime,
	//	Scope:     request.Scope}
	//accessTokenResponse.AccessToken, accessTokenResponse.Type, err = auth.CreateAccessToken(client, request.Scope)

	/**
	Validate client
		has client credentials
		if "allow_public_client disable check secret
		Check client is public
	Check available scope with requested scope
	*/

	return context.Status(200).JSON(grantType.CreateAccessToken(request.Scope))
}
