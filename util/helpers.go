package util

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"oauth2/config"
	"oauth2/dto"
	"strings"
	"time"
)

func GenerateToken() string {

	bytes := make([]byte, 20)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(bytes)
}

func DecodeHeaderCredentials(header string) (clientID string, clientSecret string) {

	parts := strings.Split(header, " ")

	if len(parts) != 2 || parts[0] != "Basic" {
		return "", ""
	}

	credentials, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ""
	}

	pieces := strings.Split(string(credentials), ":")

	clientID = pieces[0]
	clientSecret = pieces[1]

	return clientID, clientSecret
}

func PasswordHash(plain string) string {

	hash, err := bcrypt.GenerateFromPassword([]byte(plain), config.PasswordHashDefaultCost)
	if err != nil {
		panic(err)
	}
	return string(hash)
}

func PasswordVerify(hash string, plain string) bool {

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain))
	if err != nil {
		return false
	}
	return true
}

func CheckDateIsExpired(date *time.Time) bool {
	return date.Unix() < time.Now().Unix()
}

func GenerateJwt(privateKey string, params dto.JwtParams) string {

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, params)

	tokenToString, err := token.SignedString(privateKey)
	if err != nil {
		panic(err)
	}
	return tokenToString
}
