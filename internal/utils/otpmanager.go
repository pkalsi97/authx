package utils

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
)

func GenerateOtp() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func SendOtp(otp string) error {
	log.Printf("OTP SENT: %s", otp)
	return nil
}
