package http

import (
	"fmt"
	"github.com/gofiber/fiber/v2"
	"oauth2/auth"
	"oauth2/config"
	"oauth2/dto"
	"oauth2/error_handling"
	"oauth2/util"
)

// TokenController Handle new access token request
func TokenController(context *fiber.Ctx) error {

	var request dto.TokenRequest

	if err := context.BodyParser(&request); err != nil {
		return context.Status(400).JSON(error_handling.ErrorHandler("invalid_request", "The grant type was not specified in the request", ""))
	}
	request.AuthorizationHeader = context.Get("Authorization")
	grantType, err := auth.TokenRequestAssertion(request)
	if err != nil {
		return context.Status(400).JSON(err)
	}
	context.Set("Cache-Control", "no-store")
	context.Set("Pragma", "no-cache")

	return context.Status(200).JSON(grantType.GetAccessToken())
}

// AuthorizeController Handle authorization request
func AuthorizeController(context *fiber.Ctx) error {

	var authorizeRequest dto.AuthorizeRequest

	authorizeRequest.RedirectUri = context.Query("redirect_uri")
	authorizeRequest.Scope = context.Query("scope")
	authorizeRequest.State = context.Query("state")
	authorizeRequest.ClientID = context.Query("client_id")
	authorizeRequest.ResponseType = context.Query("response_type")

	authorizationUrl, err := auth.AuthorizeRequestAssertion(authorizeRequest)
	if err != nil {
		return context.Status(400).JSON(err)
	}

	return context.Status(config.RedirectStatusCode).Redirect(authorizationUrl)
}

// RevokeController Handle revoke token request
func RevokeController(context *fiber.Ctx) error {

	var request dto.RevokeTokenRequest

	if err := context.BodyParser(&request); err != nil {
		return context.Status(400).Send(nil)
	}
	err := auth.RevokeToken(request)
	if err != nil {
		return context.Status(400).JSON(err)
	}
	return context.Status(200).Send(nil)
}

// IntrospectController Respond with token data
func IntrospectController(context *fiber.Ctx) error {

	var token string

	if context.Method() == "GET" {
		token = context.Query("access_token")
	}
	if context.Method() == "POST" {
		var request dto.IntrospectRequest
		_ = context.BodyParser(&request)

		token = request.AccessToken
	}

	accessTokenFromHeader, _ := util.GetAccessTokenFromHeader(context.Get("Authorization"))

	if accessTokenFromHeader != "" {
		token = accessTokenFromHeader
	}
	if token == "" {
		// TODO: Use token type from DB?¿
		context.Set("WWW-Authenticate", fmt.Sprintf("%s realm=\"%s\"", "Bearer", config.DefaultRealm))

		return context.Status(200).Send(nil)
	}

	response, err := auth.Introspect(token)
	if err != nil {
		headerValue := fmt.Sprintf("%s realm=\"%s\", error=\"%s\"", "Bearer", config.DefaultRealm, err.(error_handling.AuthError).Err)

		if err.(error_handling.AuthError).ErrorDescription != "" {
			headerValue = fmt.Sprintf("%s, error_description=\"%s\"", headerValue, err.(error_handling.AuthError).ErrorDescription)
		}
		context.Set("WWW-Authenticate", headerValue)

		return context.Status(200).Send(nil)
	}
	return context.Status(200).JSON(response)
}
