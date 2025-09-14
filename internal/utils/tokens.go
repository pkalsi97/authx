package utils

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type IdClaims struct {
	UserId   string `json:"sub"`
	Phone    string `json:"phone"`
	Email    string `json:"email"`
	Userpool string `json:"userpool"`
	jwt.RegisteredClaims
}

type AccessClaims struct {
	UserId   string   `json:"sub"`
	Userpool string   `json:"userpool"`
	Scopes   []string `json:"scopes,omitempty"`
	Roles    []string `json:"roles,omitempty"`
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

var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey
var JWKS jwk.Set

func InitialiseTokenGen(privatek *rsa.PrivateKey, publicK *rsa.PublicKey) {
	privateKey = privatek
	publicKey = publicK
}

func InitialiseJWKS() error {
	set := jwk.NewSet()

	key, err := jwk.FromRaw(publicKey)
	if err != nil {
		return err
	}

	key.Set(jwk.KeyIDKey, "authx-key-1")
	key.Set(jwk.KeyUsageKey, "sig")
	key.Set(jwk.AlgorithmKey, "RS256")

	if err := set.AddKey(key); err != nil {
		return err
	}

	JWKS = set
	return nil
}

func GenerateTokens(userId, email, phone, userpool string, scopes []string, roles []string) (*TokenTuple, error) {

	now := time.Now()

	idClaims := &IdClaims{
		UserId:   userId,
		Phone:    phone,
		Email:    email,
		Userpool: userpool,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    "AUTHX",
			Subject:   userId,
		},
	}

	accessClaims := &AccessClaims{
		UserId:   userId,
		Userpool: userpool,
		Scopes:   scopes,
		Roles:    roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    "Authx",
			Subject:   userId,
		},
	}

	idToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, idClaims).SignedString(privateKey)
	if err != nil {
		return nil, err
	}

	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims).SignedString(privateKey)
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

func RefreshTokens(userId, email, phone, userpool string, scopes []string, roles []string) (*RefreshPair, error) {
	now := time.Now()

	idClaims := &IdClaims{
		UserId:   userId,
		Phone:    phone,
		Email:    email,
		Userpool: userpool,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    "AUTHX",
			Subject:   userId,
		},
	}

	accessClaims := &AccessClaims{
		UserId:   userId,
		Userpool: userpool,
		Scopes:   scopes,
		Roles:    roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    "Authx",
			Subject:   userId,
		},
	}

	idToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, idClaims).SignedString(privateKey)
	if err != nil {
		return nil, err
	}

	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims).SignedString(privateKey)
	if err != nil {
		return nil, err
	}

	return &RefreshPair{
		IDToken:     idToken,
		AccessToken: accessToken,
	}, nil
}

func ExtractUserIDFromIDToken(idToken string) (string, string, error) {
	claims := &IdClaims{}

	token, err := jwt.ParseWithClaims(idToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return "", "", fmt.Errorf("failed to parse ID token: %w", err)
	}

	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
		return "", "", fmt.Errorf("ID token is expired")
	}

	if !token.Valid {
		return "", "", fmt.Errorf("ID token is invalid")
	}

	if claims.UserId == "" {
		return "", "", fmt.Errorf("sub claim (user_id) missing in ID token")
	}

	return claims.UserId, claims.Userpool, nil
}

func ExtractInfo(accessToken string) (string, string, error) {
	claims := &AccessClaims{}

	token, err := jwt.ParseWithClaims(accessToken, claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to parse access token: %w", err)
	}

	if !token.Valid {
		return "", "", fmt.Errorf("invalid access token")
	}

	if claims.UserId == "" || claims.Userpool == "" {
		return "", "", fmt.Errorf("sub claim (user_id)/ user_pool_id missing in ID token")
	}

	return claims.UserId, claims.Userpool, nil

}

func ValidateAccessToken(accessToken string, requiredScopes []string, requiredRoles []string) error {
	claims := &AccessClaims{}

	token, err := jwt.ParseWithClaims(accessToken, claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return fmt.Errorf("failed to parse access token: %w", err)
	}

	if !token.Valid {
		return fmt.Errorf("invalid access token")
	}

	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		return fmt.Errorf("access token expired")
	}

	for _, scope := range requiredScopes {
		if !slices.Contains(claims.Scopes, scope) {
			return fmt.Errorf("access token missing required scope: %s", scope)
		}
	}

	for _, role := range requiredRoles {
		if !slices.Contains(claims.Roles, role) {
			return fmt.Errorf("access token missing required role: %s", role)
		}
	}

	if claims.UserId == "" || claims.Userpool == "" {
		return fmt.Errorf("sub claim (user_id)/ user_pool_id missing in ID token")
	}

	return nil

}

func ExtractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("missing Authorization header")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", fmt.Errorf("invalid Authorization header format, expected 'Bearer <token>'")
	}

	return parts[1], nil
}
