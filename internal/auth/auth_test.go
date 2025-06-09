package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

var ErrNoAuthHeader = error.New("authorization header not found")

func TestMakeJWT(t *testing.T) {
	UserID := uuid.New()
	tokenSecret := "my-secret-key"
	expiresIn := 30 * time.Minute

	tokenString, err := MakeJWT(UserID, tokenSecret, expiresIn)

	if err != nil {
		t.Errorf("Expected MakeJWT to not return an error, but got: %v", err)
	}

	if tokenString == "" {
		t.Errorf("Expected non-empty string, but got: %v", tokenString)
	}
}

func TestValidateJWT(t *testing.T) {
	UserID := uuid.New()
	tokenSecret := "my-secret-key"
	expiresIn := 30 * time.Minute

	tokenString, err := MakeJWT(UserID, tokenSecret, expiresIn)

	if err != nil {
		t.Errorf("Expected MakeJWT to not return an error, but got: %v", err)
	}

	if tokenString == "" {
		t.Errorf("Expected non-empty string, but got: %v", err)
	}

	returnedUserID, validationErr := ValidateJWT(tokenString, tokenSecret)

	if validationErr != nil {
		t.Errorf("Expected error to be: %v", validationErr)
	}

	if returnedUserID != UserID {
		t.Errorf("Returned user id %v doesn't match expected %v", returnedUserID, UserID)
	}
}

func TestValidateJWT_Expired(t *testing.T) {
	UserID := uuid.New()
	tokenSecret := "my-secret-key"
	expiresIn := 30 * time.Minute

	tokenString, err := MakeJWT(UserID, tokenSecret, expiresIn)

	if err != nil {
		t.Errorf("Expected MakeJWT to not return an error, but got: %v", err)
	}

	if tokenString == "" {
		t.Errorf("Expected non-empty string, but got: %v", err)
	}

	returnedUserID, validationErr := ValidateJWT(tokenString, tokenSecret)

	if validationErr != nil {
		t.Errorf("Expected error to be: %v", validationErr)
	}

	if returnedUserID != UserID {
		t.Errorf("Returned user id %v doesn't match expected %v", returnedUserID, UserID)
	}
}

func TestTokenString_Expired(t *testing.T) {
	UserID := uuid.New()
	tokenSecret := "my-secret-key"
	expiresIn := -30 * time.Minute

	tokenString, err := MakeJWT(UserID, tokenSecret, expiresIn)

	if err != nil {
		t.Errorf("Expected MakeJWT to not return an error, but got: %v", err)
	}

	if tokenString == "" {
		t.Errorf("Expected non-empty string, but got: %v", err)
	}

	_, validationErr := ValidateJWT(tokenString, tokenSecret)

	if validationErr == nil {
		t.Errorf("Expected an error for expired token, but got none")
	}
}

func TestAuthorization(t *testing.T) {
	headers := http.Header{
		"Authorization": {"Bearer TOKEN_STRING"},
	}

	authstring, err := GetBearerToken(headers)

	if err != nil {
		t.Errorf("Expected GetBearerToken to not return an error, but got: %v", err)
	}
	
	if authstring != "TOKEN_STRING" {
		t.Errorf("Expected to return TOKEN_STRING, but got: %v", authstring)
	}
}

func TestAuthorization_Incorrect(t *testing.T) {
	headers := http.Header{
		"Authorization": {"Bear TOKEN_STRING"},
	}

	authstring, err := GetBearerToken(headers)

	if err == nil {
		t.Errorf("Expected GetBearerToken to reuturn an error, but got none")
	}

	if authstring != "" {
		t.Errorf("Expected GetBearerToken to return an empty string, but got none")
	}
}

func TestAuthorization_Empty(t *testing.T) {
	headers := http.Header{}
	
	authstring, err := GetBearerToken(headers)

	if err != ErrNoAuthHeader {
		t.Errorf("Expected GetBearerToken to reuturn an error, but got %v", err)
	}

	if authstring != "" {
		t.Errorf("Expected GetBearerToken to return an empty string, but got none")
	}
}

func TestAuthorization_TokenString(t *testing.T) {
	headers := http.Header{
		"Authorization": {"Bearer"},
	}

	authstring, err := GetBearerToken(headers)

	if err == nil {
		t.Errorf("Expected GetBearerToken to reuturn an error, but got none")
	}

	if authstring != "" {
		t.Errorf("Expected GetBearerToken to return an empty string, but got none")
	}
}

func TestAuthorization_TokenString_Whtiespace(t *testing.T) {
	headers := http.Header{
		"Authorization": {"Bearer		"},
	}

	authstring, err := GetBearerToken(headers)

	if err == nil {
		t.Errorf("Expected GetBearerToken to reuturn an error, but got none")
	}

	if authstring != "" {
		t.Errorf("Expected GetBearerToken to return an empty string, but got none")
	}
}