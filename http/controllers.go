package http

import (
	"github.com/gofiber/fiber/v2"
	"oauth2/auth"
	"oauth2/dto"
	"oauth2/util"
)

func TokenController(context *fiber.Ctx) error {

	var request dto.TokenRequest

	if err := context.BodyParser(&request); err != nil {
		return context.Status(400).Send(nil)
	}
	authorizationHeader := context.Get("Authorization")
	if authorizationHeader != "" {
		request.ClientID, request.ClientSecret = util.DecodeHeaderCredentials(authorizationHeader)
	}
	grantType, err := auth.ClientAssertion(request)
	if err != nil {
		return context.Status(400).JSON(err)
	}
	return context.Status(200).JSON(grantType.CreateAccessToken(request.Scope))
}

func AuthorizeController(context *fiber.Ctx) error {

	var authorizeRequest dto.AuthorizeRequest

	authorizeRequest.RedirectUri = context.Query("redirect_uri")
	authorizeRequest.Scope = context.Query("scope")
	authorizeRequest.State = context.Query("state")
	authorizeRequest.ClientID = context.Query("client_id")
	authorizeRequest.ResponseType = context.Query("response_type")

	_ = auth.AuthorizeAssertion(authorizeRequest)

	return context.Status(200).Send(nil)
}
