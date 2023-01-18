package repository

import "errors"

func FindUserByUsername(username string) (User, error) {

	var user User

	databaseConnection.Model(&User{}).First(&user, "username = ?", username)

	if user.Username == "" {
		return user, errors.New("user not found")
	}
	return user, nil
}
