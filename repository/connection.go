package repository

import (
	"fmt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"time"
)

type Client struct {
	ID        string            `gorm:"primary_key;column:client_id;type:varchar(36);default:uuid_generate_v4()"`
	Secret    string            `gorm:"column:client_secret;type:varchar(255)"`
	Name      string            `gorm:"column:name;type:varchar(128);not null"`
	GrantType []ClientGrantType `gorm:"foreignKey:ClientID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Scope     string            `gorm:"column:scope;type:varchar(4000);not null"`
}

type ClientGrantType struct {
	ID        int    `gorm:"primary_key;column:id;type:integer"`
	ClientID  string `gorm:"type:varchar(36);index:composite,unique;not null"`
	GrantType string `gorm:"type:varchar(28);index:composite,unique;column:grant_type"`
}

type AccessToken struct {
	Token     string    `gorm:"primary_key;type:varchar(40)"`
	Scope     string    `gorm:"type:varchar(4000);not null"`
	ClientID  string    `gorm:"column:client_id;type:varchar(36)"`
	Client    Client    `gorm:"references:ID"`
	ExpiresIn time.Time `gorm:"column:expires_in;type:timestamp;not null"`
}

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
		&AccessToken{})

	if err != nil {
		panic(err)
	}
}
