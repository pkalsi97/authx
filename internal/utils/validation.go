package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"unicode"

	"github.com/go-playground/validator/v10"
)

var Validate *validator.Validate

func InitaliseValidator() {
	Validate = validator.New()
}

func ValidateInput(input any) error {
	return Validate.Struct(input)
}

func CheckHeaders(r *http.Request, headers []string) error {
	missing := []string{}

	for _, h := range headers {
		if r.Header.Get(h) == "" {
			missing = append(missing, h)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required headers: %v", missing)
	}
	return nil
}

func BindAndValidate[T any](r *http.Request, method string) (*T, error) {

	if r.Method != method {
		return nil, fmt.Errorf("invalid request method: got %s, want %s", r.Method, method)
	}
	defer r.Body.Close()

	var input T
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		return nil, fmt.Errorf("decode error: %w", err)
	}

	if err := ValidateInput(&input); err != nil {
		return nil, fmt.Errorf("validation error: %w", err)
	}

	return &input, nil
}

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
