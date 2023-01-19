package test

import (
	"encoding/base64"
	"fmt"
	"oauth2/repository"
	"oauth2/util"
	"testing"
)

// TestGenerateToken GenerateToken
func TestGenerateToken(t *testing.T) {

	token := util.GenerateToken()

	if len(token) != 40 {
		t.Fatalf("Invalid token %s", token)
	}
}

// TestDecodeHeaderCredentials DecodeHeaderCredentials
func TestDecodeHeaderCredentials(t *testing.T) {

	clientIdExpected := "id"
	secretExpected := "secret"

	header := fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", clientIdExpected, secretExpected))))

	clientIdActual, secretActual := util.DecodeHeaderCredentials(header)

	if clientIdActual != clientIdExpected {
		t.Fatalf("Client fail assertion: expected: %s, actual: %s", clientIdExpected, clientIdActual)
	}
	if secretActual != secretExpected {
		t.Fatalf("Secret fail assertion: expected: %s, actual: %s", secretExpected, secretActual)
	}
}

// TestCompareScopes TestCompareScopes
func TestCompareScopes(t *testing.T) {
	current := "read"
	available := "read write"

	result, err := util.CompareScopes(available, current)
	if result == false {
		t.Fatalf("Scope not allowed: %s", err.Error())
	}
}

// TestNormalizeScopeList TestNormalizeScopeList
func TestNormalizeScopeList(t *testing.T) {

	var scopeList []repository.Scope

	scopeList = append(scopeList, repository.Scope{Name: "read", IsDefault: true})
	scopeList = append(scopeList, repository.Scope{Name: "write", IsDefault: true})

	result := util.NormalizeScopeList(scopeList)

	if result != "read write" {
		t.Fatalf("Unespected scope normalized result: %s", result)
	}
}
