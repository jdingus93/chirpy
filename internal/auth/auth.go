package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	result, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(result), nil
}

func CheckPasswordHash(hash, password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	claims := jwt.RegisteredClaims{
		Issuer: "chirpy",
		IssuedAt: jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
		Subject: userID.String(),
	}
	fmt.Printf("Token expires at: %v\n", claims.ExpiresAt.Time)
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	var claims jwt.RegisteredClaims
	_ , err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error){
		return []byte(tokenSecret), nil
	})
	fmt.Printf("Token validated at: %v", err)
	fmt.Printf("Extracted Subject: %v'\n", claims.Subject)

	if err != nil {
		return uuid.UUID{}, err
	}
	parsed, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.UUID{}, err
	}
	return parsed, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	authHeader, ok := headers["Authorization"]
	if !ok {
		return "", errors.New("authorization header missing")
	}

	if len(authHeader) == 0 {
			return "", errors.New("authorization heeader empty")
		}

	if len(authHeader[0]) < 7 {
		return "", errors.New("authorization header too short")
	}

	if authHeader[0][0:7] != "Bearer " {
		return "", errors.New("prefix doesn't begin with Bearer")
	}

		return authHeader[0][7:], nil
}

func MakeRefreshToken() (string, error) {
	data := make([]byte, 32)
	_, err := rand.Read(data)
	if err != nil {
		return "", err
	}
	token := hex.EncodeToString(data)
	return token, nil
}