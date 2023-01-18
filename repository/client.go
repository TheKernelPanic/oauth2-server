package repository

import "errors"

func FindClientById(id string) (Client, error) {

	var client Client

	databaseConnection.Model(&Client{}).Preload("GrantType").Preload("JwtConfig").First(&client, "client_id = ?", id)

	if client.ID == "" {
		return client, errors.New("client not found")
	}

	return client, nil
}
