package utils

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var jwtSecret []byte

type IdClaims struct {
	UserId string `json:"sub"`
	Phone  string `json:"phone"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

type AccessClaims struct {
	UserId string `json:"sub"`
	jwt.RegisteredClaims
}

type TokenTuple struct {
	IDToken      string
	AccessToken  string
	RefreshToken string
}

type RefreshPair struct {
	IDToken     string
	AccessToken string
}

func IntialseTokenGen(key string) {
	jwtSecret = []byte(key)
}

func GenerateTokens(userId, email, phone string) (*TokenTuple, error) {

	now := time.Now()

	idClaims := &IdClaims{
		UserId: userId,
		Phone:  phone,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    "AUTHX",
			Subject:   userId,
		},
	}

	accessClaims := &AccessClaims{
		UserId: userId,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    "Authx",
			Subject:   userId,
		},
	}

	idToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, idClaims).SignedString(jwtSecret)
	if err != nil {
		return nil, err
	}

	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims).SignedString(jwtSecret)
	if err != nil {
		return nil, err
	}

	refreshToken := uuid.NewString()

	return &TokenTuple{
		IDToken:      idToken,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func RefreshTokens(userId, email, phone string) (*RefreshPair, error) {
	now := time.Now()

	idClaims := &IdClaims{
		UserId: userId,
		Phone:  phone,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    "AUTHX",
			Subject:   userId,
		},
	}

	accessClaims := &AccessClaims{
		UserId: userId,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    "Authx",
			Subject:   userId,
		},
	}

	idToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, idClaims).SignedString(jwtSecret)
	if err != nil {
		return nil, err
	}

	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims).SignedString(jwtSecret)
	if err != nil {
		return nil, err
	}

	return &RefreshPair{
		IDToken:     idToken,
		AccessToken: accessToken,
	}, nil
}

func ExtractUserIDFromIDToken(idToken string) (string, error) {
	claims := &IdClaims{}

	token, err := jwt.ParseWithClaims(idToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil {
		return "", fmt.Errorf("failed to parse ID token: %w", err)
	}

	if !token.Valid {
		return "", fmt.Errorf("ID token is invalid")
	}

	if claims.UserId == "" {
		return "", fmt.Errorf("sub claim (user_id) missing in ID token")
	}

	return claims.UserId, nil
}
