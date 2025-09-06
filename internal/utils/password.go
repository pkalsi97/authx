package utils

import (
	"golang.org/x/crypto/bcrypt"
)

func CreateHash(key string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(key), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedBytes), nil
}

func CompareHash(hashed, key string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(key))
	return err == nil
}
