package utils

import (
	"crypto/rand"
	"encoding/base32"
)

func GenerateAPIKey() (string, error) {
	b := make([]byte, 9) // 9 bytes = 72 bits
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}
