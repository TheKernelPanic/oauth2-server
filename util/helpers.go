package util

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"net/url"
	"oauth2/config"
	"oauth2/repository"
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

func GenerateAuthorizationCode() string {
	return GenerateToken()
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
	if len(pieces) == 2 {
		clientSecret = pieces[1]
	}
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

func BuildUrlAuthorizationCode(redirectUri string, scope string, state string, code string) string {

	urlParsed := buildUrlAuthorization(redirectUri, scope, state)

	urlQuery := urlParsed.Query()
	urlQuery.Add("code", code)

	urlParsed.RawQuery = urlQuery.Encode()

	return urlParsed.String()
}

func BuildUrlAuthorizationImplicit(redirectUri string, scope string, state string, accessToken string) string {

	urlParsed := buildUrlAuthorization(redirectUri, scope, state)

	urlParsed.Fragment = fmt.Sprintf(
		"access_token=%s&token_type=%s&expires_in=%d",
		accessToken,
		"bearer",
		config.AccessTokenLifeTime)

	return urlParsed.String()
}

func buildUrlAuthorization(redirectUri string, scope string, state string) *url.URL {

	urlParsed, _ := url.Parse(redirectUri)

	urlQuery := urlParsed.Query()
	if state != "" {
		urlQuery.Add("state", state)
	}
	if scope != "" {
		urlQuery.Add("scope", scope)
	}
	urlParsed.RawQuery = urlQuery.Encode()

	return urlParsed
}

func NormalizeScopeList(list []repository.Scope) string {

	var delimited []string
	for _, scope := range list {
		delimited = append(delimited, scope.Name)
	}
	return strings.Join(delimited, " ")
}

func CompareScopes(available string, current string) (bool, error) {

	availableList := strings.Split(available, " ")
	currentList := strings.Split(current, " ")

	var found bool
	for _, currentElement := range currentList {
		found = false
		for _, availableElement := range availableList {
			if currentElement == availableElement {
				found = true
			}
		}
		if !found {
			return false, errors.New(currentElement)
		}
	}
	return true, nil
}
