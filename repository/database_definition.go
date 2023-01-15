package repository

import (
	"database/sql"
	"time"
)

type Client struct {
	ID          string            `gorm:"primary_key;column:client_id;type:varchar(36);default:uuid_generate_v4()"`
	Secret      string            `gorm:"column:client_secret;type:varchar(255)"`
	Name        string            `gorm:"column:name;type:varchar(128);not null"`
	GrantType   []ClientGrantType `gorm:"foreignKey:ClientID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Scope       string            `gorm:"column:scope;type:varchar(4000);not null"`
	RedirectUri string            `gorm:"column:redirect_uri;type:varchar(2000)"`
}

func (Client) TableName() string {
	return "client"
}

type ClientGrantType struct {
	ID        uint   `gorm:"primary_key;column:id;type:integer"`
	ClientID  string `gorm:"type:varchar(36);index:composite,unique;not null"`
	GrantType string `gorm:"type:varchar(28);index:composite,unique;column:grant_type"`
}

func (ClientGrantType) TableName() string {
	return "client_grant_type"
}

type AccessToken struct {
	Token    string `gorm:"primary_key;type:varchar(40)"`
	Scope    string `gorm:"type:varchar(4000);not null"`
	User     User   `gorm:"references:ID"`
	UserID   sql.NullInt32
	ClientID string    `gorm:"column:client_id;type:varchar(36);not null"`
	Client   Client    `gorm:"references:ID"`
	Expires  time.Time `gorm:"column:expires;type:timestamp;not null"`
}

func (AccessToken) TableName() string {
	return "access_token"
}

type User struct {
	ID                 uint                `gorm:"primary_key;column:id;type:integer"`
	Username           string              `gorm:"type:varchar(128);not null;uniqueIndex"`
	Password           string              `gorm:"type:varchar(255);not null"`
	FirstName          string              `gorm:"type:varchar(128)"`
	LastName           string              `gorm:"type:varchar(128)"`
	Email              string              `gorm:"type:varchar(320);not null;uniqueIndex"`
	EmailVerified      bool                `gorm:"type:boolean;not null;default:false"`
	Scope              string              `gorm:"type:varchar(4000)"`
	AccessTokens       []AccessToken       `gorm:"foreignKey:UserID;references:ID;"`
	RefreshTokens      []RefreshToken      `gorm:"foreignKey:UserID;references:ID;"`
	AuthorizationCodes []AuthorizationCode `gorm:"foreignKey:UserID;references:ID;"`
}

func (User) TableName() string {
	return "user"
}

type RefreshToken struct {
	Token    string `gorm:"primary_key;type:varchar(40)"`
	Scope    string `gorm:"type:varchar(4000);not null"`
	User     User   `gorm:"references:ID"`
	UserID   sql.NullInt32
	ClientID string     `gorm:"column:client_id;type:varchar(36)"`
	Client   Client     `gorm:"references:ID"`
	Expires  *time.Time `gorm:"column:expires;type:timestamp"`
}

func (RefreshToken) TableName() string {
	return "refresh_token"
}

type AuthorizationCode struct {
	Code        string `gorm:"primary_key;type:varchar(40)"`
	RedirectUri string `gorm:"column:redirect_uri;type:varchar(2000)"`
	IdToken     string `gorm:"column:id_token;type:varchar(1000)"`
	User        User   `gorm:"references:ID"`
	UserID      sql.NullInt32
	ClientID    string    `gorm:"column:client_id;type:varchar(36);not null"`
	Client      Client    `gorm:"references:ID"`
	Expires     time.Time `gorm:"column:expires;type:timestamp;not null"`
	Scope       string    `gorm:"type:varchar(4000);not null"`
}

func (AuthorizationCode) TableName() string {
	return "authorization_code"
}

type Jwt struct {
	ClientID  string `gorm:"column:client_id;type:varchar(36);not null"`
	Client    Client `gorm:"references:ID"`
	Subject   string `gorm:"column:subject;type:varchar(80)"`
	PublicKey string `gorm:"column:public_key;type:varchar(2000)"`
}

func (Jwt) TableName() string {
	return "jwt"
}
