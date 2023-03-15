package repository

import (
	"fmt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var databaseConnection *gorm.DB

func InitDatabaseConnection(host string, user string, password string, database string, port string) {

	var connectionString = fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable",
		host,
		user,
		password,
		database,
		port)

	var err error
	databaseConnection, err = gorm.Open(postgres.New(postgres.Config{
		DSN:                  connectionString,
		PreferSimpleProtocol: true,
	}), &gorm.Config{})

	databaseConnection.AutoMigrate(
		&Client{},
		&ClientGrantType{},
		&User{},
		&RefreshToken{},
		&AuthorizationCode{},
		&JwtConfig{},
		&Scope{},
		&AccessToken{},
		&PublicKey{})

	if err != nil {
		panic(err)
	}
}
