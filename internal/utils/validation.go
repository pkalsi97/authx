package utils

import (
	"strings"
	"unicode"
)

func IsValidPhone(phone string) (string, bool) {
	if len(phone) > 10 {
		phone = phone[len(phone)-10:]
	}

	if len(phone) != 10 {
		return "", false
	}

	for _, ch := range phone {
		if !unicode.IsDigit(ch) {
			return "", false
		}
	}

	return "+91" + phone, true
}

func IsValidEmail(email string) bool {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	local, domain := parts[0], parts[1]

	if local == "" || domain == "" {
		return false
	}

	for _, ch := range email {
		if unicode.IsSpace(ch) {
			return false
		}
	}

	if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") {
		return false
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	if !strings.Contains(domain, ".") {
		return false
	}

	return true
}
