package util

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
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