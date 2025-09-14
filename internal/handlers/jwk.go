package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkalsi97/authx/internal/utils"
)

func JWKSHandler(jwks jwk.Set) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		jsonBytes, err := json.Marshal(jwks)
		if err != nil {
			utils.WriteError(w, http.StatusInternalServerError, "failed to marshal JWKS", err.Error())
			return
		}

		w.Write(jsonBytes)
	}
}
