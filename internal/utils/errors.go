package utils

import (
	"encoding/json"
	"net/http"

	"github.com/pkalsi97/authx/internal/models"
)

func WriteError(w http.ResponseWriter, status int, message string, details string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	resp := models.ErrorResponse{
		Error:   message,
		Details: details,
	}
	json.NewEncoder(w).Encode(resp)
}
