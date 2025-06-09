package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

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