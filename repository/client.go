package repository

import "errors"

func FindClientById(id string) (Client, error) {

	var client Client

	databaseConnection.Model(&Client{}).Preload("GrantType").First(&client, "client_id = ?", id)

	if client.ID == "" {
		return client, errors.New("client not found")
	}

	return client, nil
}

func FindJwtByClientId(id string) (Jwt, error) {

	var jwt Jwt

	databaseConnection.Model(&Jwt{}).First(&jwt, "client_id = ?", id)

	if jwt.ClientID == "" {
		return jwt, errors.New("jwt client not found")
	}

	return jwt, nil
}
