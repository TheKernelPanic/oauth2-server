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
		return err
	}
	if request.GrantType == "" {
		return context.Status(400).SendString("the grant type was not specified in the request")
	}
	authorizationHeader := context.Get("Authorization")
	if authorizationHeader != "" {
		request.ClientID, request.ClientSecret = util.DecodeHeaderCredentials(authorizationHeader)
	}
	grantType, err := auth.ClientAssertion(request)
	if err != nil {
		return context.Status(401).SendString(err.Error())
	}
	return context.Status(200).JSON(grantType.CreateAccessToken(request.Scope))
}
