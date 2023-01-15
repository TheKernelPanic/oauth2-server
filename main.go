package main

import (
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
	"oauth2/http"
	"oauth2/repository"
	"os"
)

func main() {

	err := godotenv.Load()
	if err != nil {
		panic(err)
	}

	repository.InitDatabaseConnection(
		os.Getenv("DATABASE_HOST"),
		os.Getenv("DATABASE_USER"),
		os.Getenv("DATABASE_PASSWORD"),
		os.Getenv("DATABASE_NAME"),
		os.Getenv("DATABASE_PORT"))
	if err != nil {
		panic(err)
	}

	appServer := fiber.New()

	oAuthGroup := appServer.Group("/oauth/v2")
	oAuthGroup.Post("/token", http.TokenController)
	oAuthGroup.Get("/authorize", http.AuthorizeController)

	err = appServer.Listen(fmt.Sprintf("%s:%s", os.Getenv("APPLICATION_HOST"), os.Getenv("APPLICATION_PORT")))
	if err != nil {
		panic(err)
	}
}
