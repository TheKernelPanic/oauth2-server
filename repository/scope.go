package repository

import "errors"

func FindDefaultScope() ([]Scope, error) {

	var scope []Scope

	databaseConnection.Model(&Scope{}).Find(&scope, "default = ?", true)

	if len(scope) == 0 {
		return scope, errors.New("default scope not found")
	}

	return scope, nil
}
