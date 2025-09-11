package handlers

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/pkalsi97/authx/internal/db"
	"github.com/pkalsi97/authx/internal/models"
	"github.com/pkalsi97/authx/internal/router"
	"github.com/pkalsi97/authx/internal/utils"
)

var ownerRoutes = []router.Route{
	{
		Method:  http.MethodPost,
		Pattern: regexp.MustCompile(`^create$`),
		Handler: func(w http.ResponseWriter, r *http.Request, _ []string) {
			createAdmin(w, r)
		},
	},
	{
		Method:  http.MethodPost,
		Pattern: regexp.MustCompile(`^([^/]+)/apikeys$`),
		Handler: func(w http.ResponseWriter, r *http.Request, matches []string) {
			createAPIKey(w, r, matches[1])
		},
	},
	{
		Method:  http.MethodPatch,
		Pattern: regexp.MustCompile(`^([^/]+)/apikeys/([^/]+)/disable$`),
		Handler: func(w http.ResponseWriter, r *http.Request, matches []string) {
			disableAPIKey(w, r, matches[1], matches[2])
		},
	},
}

var userpoolRoutes = []router.Route{
	{
		Method:  http.MethodPost,
		Pattern: regexp.MustCompile(`^create$`),
		Handler: func(w http.ResponseWriter, r *http.Request, matches []string) {
			createUserpool(w, r)
		},
	},
	{
		Method:  http.MethodPatch,
		Pattern: regexp.MustCompile(`^([^/]+)$`),
		Handler: func(w http.ResponseWriter, r *http.Request, matches []string) {
			updateUserpool(w, r, matches[1])
		},
	},
	{
		Method:  http.MethodDelete,
		Pattern: regexp.MustCompile(`^([^/]+)$`),
		Handler: func(w http.ResponseWriter, r *http.Request, matches []string) {
			deleteUserpool(w, r, matches[1])
		},
	},
}

func OwnerRouter(w http.ResponseWriter, r *http.Request) {
	router.MatchAndServe(w, r, "/api/v1/admin/owners/", ownerRoutes)
}

func UserPoolRouter(w http.ResponseWriter, r *http.Request) {
	router.MatchAndServe(w, r, "/api/v1/admin/user-pools/", userpoolRoutes)
}

/*
-----------------------

	Internal Functions

-----------------------
*/
// CreateAdmin godoc
// @Summary      Create an admin
// @Description  Create a new admin in the system
// @Tags         Admins
// @Accept       json
// @Produce      json
// @Param        admin  body      models.CreateAdminRequest  true  "Admin input"
// @Success      201  {object}  models.CreateAdminResponse
// @Failure      400  {object}  models.ErrorResponse "Invalid request body or validation error"
// @Failure      500  {object}  models.ErrorResponse "Database error"
// @Router       /api/v1/admin/owners/create [post]
func createAdmin(w http.ResponseWriter, r *http.Request) {
	var input models.CreateAdminRequest

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "invalid Request Body", err.Error())
		return
	}

	if err := utils.ValidateInput(input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Validation Error", err.Error())
		return
	}

	var result models.CreateAdminResponse
	query := `INSERT INTO owners (email, name, organization) VALUES ($1, $2, $3) RETURNING id, created_at`
	args := []any{input.Email, input.Name, input.Organization}
	if err := db.QueryRowAndScan(r.Context(), query, args, &result.Id, &result.CreatedAt); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, resp.Status, "Database Error", resp.Message)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(result)
}

// CreateAPIKey godoc
// @Summary      Generate an API key for an owner
// @Description  Creates a new API key for the given owner/admin. The key is returned in plaintext once.
// @Tags         Admins
// @Accept       json
// @Produce      json
// @Param        adminId   path      string  true  "Owner/Admin ID"
// @Success      201  {object}  models.CreateAPIKeyResponse "Created API Key"
// @Failure      400  {object}  models.ErrorResponse "Invalid request"
// @Failure      500  {object}  models.ErrorResponse "Server error"
// @Router       /api/v1/admin/owners/{adminId}/apikeys [post]
func createAPIKey(w http.ResponseWriter, r *http.Request, adminId string) {
	apiKey, err := utils.GenerateAPIKey()
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Falied to Generate Key", err.Error())
		return
	}

	var response models.CreateAPIKeyResponse
	query := `INSERT INTO owners_api_keys (owner_id, key_hash) VALUES ($1, $2) RETURNING key_hash, created_at`
	args := []any{adminId, apiKey}
	if err := db.QueryRowAndScan(r.Context(), query, args, &response.Key, &response.CreatedAt); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, resp.Status, "Database Error", resp.Message)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// DisableAPIKey godoc
// @Summary      Disable an API key
// @Description  Marks an API key as revoked (revoked=true) for a specific owner/admin.
// @Tags         Admins
// @Accept       json
// @Produce      json
// @Param        adminId   path      string  true  "Owner/Admin ID"
// @Param        apiKey    path      string  true  "API Key value to disable"
// @Success      200  {object}  models.DisableAPIKeyResponse "API Key revoked successfully"
// @Failure      400  {object}  models.ErrorResponse "Invalid request"
// @Failure      500  {object}  models.ErrorResponse "Server error"
// @Router       /api/v1/admin/owners/{adminId}/apikeys/{apiKey}/disable [patch]
func disableAPIKey(w http.ResponseWriter, r *http.Request, adminId, apiKey string) {
	var response models.DisableAPIKeyResponse

	query := `UPDATE owners_api_keys SET revoked = TRUE WHERE owner_id = $1 AND key_hash = $2 RETURNING id, revoked;`
	args := []any{adminId, apiKey}
	if err := db.QueryRowAndScan(r.Context(), query, args, &response.Id, &response.Revoked); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, resp.Status, "Database Error", resp.Message)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// CreateUserPool godoc
// @Summary      Create a user pool
// @Description  Create a new user pool for grouping users
// @Tags         Userpools
// @Accept       json
// @Produce      json
// @Param        X-API-KEY   header    string                      true  "Owner API Key"
// @Param        userPool    body      models.CreateUserPoolRequest true  "User Pool input"
// @Success      201  {object}  models.CreateUserPoolResponse
// @Failure      400  {object}  models.ErrorResponse "Invalid request body"
// @Failure      401  {object}  models.ErrorResponse "Invalid API Key"
// @Failure      500  {object}  models.ErrorResponse "Database error"
// @Router       /api/v1/admin/user-pools/create [post]
func createUserpool(w http.ResponseWriter, r *http.Request) {
	var input models.CreateUserPoolRequest
	apiKey := r.Header.Get("X-API-KEY")
	if apiKey == "" {
		utils.WriteError(w, http.StatusUnauthorized, "Missing API Key", "X-API-KEY is not present in the headers")
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "invalid Request Body", err.Error())
		return
	}

	if err := utils.ValidateInput(input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Validation Error", err.Error())
		return
	}

	var ownerId string
	query := `SELECT owner_id FROM owners_api_keys WHERE key_hash = $1 AND revoked = false`
	args := []any{apiKey}
	if err := db.QueryRowAndScan(r.Context(), query, args, &ownerId); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, http.StatusUnauthorized, "Invalid API Key", resp.Message)
		return
	}

	var result models.CreateUserPoolResponse
	query = `INSERT INTO user_pools (owner_id, name, schema) VALUES ($1, $2, $3) RETURNING id, created_at`
	args = []any{ownerId, input.Name, input.Schema}
	if err := db.QueryRowAndScan(r.Context(), query, args, &result.Id, &result.CreatedAt); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, http.StatusUnauthorized, "Invalid API Key", resp.Message)
		return
	}

	roleQuery := `
		INSERT INTO roles (user_pool_id, name, permissions)
		VALUES
			($1, 'user',  '["profile:read", "profile:update", "password:reset"]'::jsonb),
			($1, 'admin', '["profile:read", "profile:update", "password:reset", "users:manage"]'::jsonb);
`
	if _, err := db.GetDb().Exec(r.Context(), roleQuery, result.Id); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, http.StatusInternalServerError, "Failed to seed default roles", resp.Message)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

// UpdateUserPool godoc
// @Summary      Update a user pool
// @Description  Updates the name or schema of an existing user pool identified by its ID. The owner is authenticated via X-API-KEY.
// @Tags         Userpools
// @Accept       json
// @Produce      json
// @Param        X-API-KEY   header    string                      true  "Owner API Key"
// @Param        userpoolId  path      string                      true  "User Pool ID"
// @Param        userPool    body      models.UpdateUserPoolRequest true  "Updated User Pool data"
// @Success      200  {object}  models.UpdateUserPoolResponse
// @Failure      400  {object}  models.ErrorResponse "Invalid request body"
// @Failure      401  {object}  models.ErrorResponse "Invalid API Key"
// @Failure      404  {object}  models.ErrorResponse "User pool not found"
// @Failure      500  {object}  models.ErrorResponse "Failed to update user pool"
// @Router       /api/v1/admin/user-pools/{userpoolId} [patch]
func updateUserpool(w http.ResponseWriter, r *http.Request, userpoolId string) {
	var input models.UpdateUserPoolRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request Body", err.Error())
		return
	}

	if err := utils.ValidateInput(input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Validation Error", err.Error())
		return
	}

	apiKey := r.Header.Get("X-API-KEY")
	var ownerId string
	query := `SELECT owner_id FROM owners_api_keys WHERE key_hash = $1 AND revoked = false`
	args := []any{apiKey}
	if err := db.QueryRowAndScan(r.Context(), query, args, &ownerId); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, http.StatusUnauthorized, "Invalid API Key", resp.Message)
		return
	}

	var response models.UpdateUserPoolResponse
	query = `UPDATE user_pools
		SET name = $1, schema = $2, updated_at = NOW()
		WHERE id = $3 AND owner_id = $4
		RETURNING id`
	args = []any{input.Name, input.Schema, userpoolId, ownerId}
	if err := db.QueryRowAndScan(r.Context(), query, args, &response.Id); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, http.StatusUnauthorized, "Database error", resp.Message)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// DeleteUserPool godoc
// @Summary      Delete a user pool
// @Description  Deletes an existing user pool identified by its ID. Only the owner with a valid API key can perform this action.
// @Tags         Userpools
// @Accept       json
// @Produce      json
// @Param        X-API-KEY   header    string  true  "Owner API Key"
// @Param        userpoolId  path      string  true  "User Pool ID"
// @Success      200  {object}  map[string]string "Successfully deleted"
// @Failure      401  {object}  models.ErrorResponse "Invalid API Key"
// @Failure      404  {object}  models.ErrorResponse "User pool not found"
// @Failure      500  {object}  models.ErrorResponse "Failed to delete user pool"
// @Router       /api/v1/admin/user-pools/{userpoolId} [delete]
func deleteUserpool(w http.ResponseWriter, r *http.Request, userpoolId string) {
	apiKey := r.Header.Get("X-API-KEY")

	var ownerId string
	query := `SELECT owner_id FROM owners_api_keys WHERE key_hash = $1 AND revoked = false`
	args := []any{apiKey}
	if err := db.QueryRowAndScan(r.Context(), query, args, &ownerId); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, http.StatusUnauthorized, "Invalid API Key", resp.Message)
		return
	}

	result, err := db.GetDb().Exec(
		r.Context(),
		`DELETE FROM user_pools WHERE id = $1 AND owner_id = $2`,
		userpoolId, ownerId,
	)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Failed to delete user pool", err.Error())
		return
	}

	if result.RowsAffected() == 0 {
		utils.WriteError(w, http.StatusNotFound, "User pool not found", "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User pool deleted successfully"})
}
