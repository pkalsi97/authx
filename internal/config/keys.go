package config

import (
	"crypto/rsa"
	"log"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

type Keys struct {
	Private *rsa.PrivateKey
	Public  *rsa.PublicKey
}

func LoadKeys(privatePath, publicPath string) (*Keys, error) {

	privData, err := os.ReadFile(privatePath)
	if err != nil {
		return nil, err
	}

	pubData, err := os.ReadFile(publicPath)
	if err != nil {
		return nil, err
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privData)
	if err != nil {
		return nil, err
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(pubData)
	if err != nil {
		log.Fatalf("failed to parse public key: %v", err)
	}

	return &Keys{
		Private: privateKey,
		Public:  publicKey,
	}, nil
}
