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
// @Summary      Create an owner
// @Description  Create a new owner in the system
// @Tags         owners
// @Accept       json
// @Produce      json
// @Param        owner  body      models.OwnerInput  true  "Owner input"
// @Success      201  {object}  models.Owner
// @Failure      400  {string}  string  "invalid Request Body"
// @Failure      500  {string}  string  "Failed to insert owner"
// @Router       /api/v1/admin/owners [post]
func createAdmin(w http.ResponseWriter, r *http.Request) {
	var input models.OwnerInput

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "invalid Request Body", err.Error())
		return
	}

	var owner models.Owner
	row := db.GetDb().QueryRow(
		r.Context(),
		`INSERT INTO owners (email, name, organization)
		 VALUES ($1, $2, $3)
		 RETURNING id, email, name, organization, created_at, updated_at`,
		input.Email, input.Name, input.Organization,
	)

	if err := row.Scan(&owner.ID, &owner.Email, &owner.Organization, &owner.Name, &owner.CreatedAt, &owner.UpdatedAt); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Falied to insert owner", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(owner)
}

// CreateAPIKey godoc
// @Summary      Generate an API key for an owner
// @Description  Creates a new API key for the given owner/admin. The key is returned in plaintext once.
// @Tags         owners
// @Produce      json
// @Param        adminId   path      string  true  "Owner/Admin ID"
// @Success      201  {object}  models.OwnerAPIKey  "Created API Key"
// @Failure      400  {object}  models.ErrorResponse "Invalid request"
// @Failure      500  {object}  models.ErrorResponse "Server error"
// @Router       /api/v1/admin/owners/{adminId}/apikeys [post]

func createAPIKey(w http.ResponseWriter, r *http.Request, adminId string) {
	apiKey, err := utils.GenerateAPIKey()

	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Falied to Generate Key", err.Error())
		return
	}

	var ownerApiKey models.OwnerAPIKey
	row := db.GetDb().QueryRow(
		r.Context(),
		`INSERT INTO owners_api_keys (owner_id, key_hash)
		VALUES ($1, $2)
		RETURNING id, owner_id, key_hash, created_at, revoked`,
		adminId, apiKey,
	)

	if err := row.Scan(&ownerApiKey.ID, &ownerApiKey.OwnerID, &ownerApiKey.KeyHash, &ownerApiKey.CreatedAt, &ownerApiKey.Revoked); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Falied to insert owner", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(ownerApiKey)
}

// DisableAPIKey godoc
// @Summary      Disable an API key
// @Description  Marks an API key as revoked (revoked=true) for a specific owner/admin.
// @Tags         owners
// @Accept       json
// @Produce      json
// @Param        adminId   path      string  true  "Owner/Admin ID"
// @Param        apiKey    path      string  true  "API Key value to disable"
// @Success      200  {object}  models.OwnerAPIKey  "Updated API Key with revoked=true"
// @Failure      400  {object}  models.ErrorResponse "Invalid request"
// @Failure      500  {object}  models.ErrorResponse "Server error"
// @Router       /api/v1/admin/owners/{adminId}/apikeys/{apiKey}/disable [patch]
func disableAPIKey(w http.ResponseWriter, r *http.Request, adminId, apiKey string) {
	var ownerApiKey models.OwnerAPIKey
	row := db.GetDb().QueryRow(
		r.Context(),
		`UPDATE owners_api_keys
		SET revoked = TRUE
		WHERE owner_id = $1 AND key_hash = $2
		RETURNING id, owner_id, key_hash, created_at, revoked;
		`,
		adminId, apiKey,
	)

	if err := row.Scan(&ownerApiKey.ID, &ownerApiKey.OwnerID, &ownerApiKey.KeyHash, &ownerApiKey.CreatedAt, &ownerApiKey.Revoked); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Failed to revoke API key", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ownerApiKey)
}

// CreateUserPool godoc
// @Summary      Create a new user pool
// @Description  Creates a new user pool for the owner identified by the API key. The schema will be stored as JSON.
// @Tags         userpools
// @Accept       json
// @Produce      json
// @Param        X-API-KEY  header    string            true  "Owner API Key"
// @Param        userPool    body      models.UserPoolInput  true  "User Pool input"
// @Success      200  {object}  models.UserPool
// @Failure      400  {object}  models.ErrorResponse "Invalid request body"
// @Failure      401  {object}  models.ErrorResponse "Invalid API Key"
// @Failure      500  {object}  models.ErrorResponse "Failed to create user pool"
// @Router       /api/v1/admin/user-pools/create [post]
func createUserpool(w http.ResponseWriter, r *http.Request) {
	var input models.UserPoolInput

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "invalid Request Body", err.Error())
		return
	}

	apiKey := r.Header.Get("X-API-KEY")
	var ownerId string

	err := db.GetDb().QueryRow(
		r.Context(),
		`SELECT owner_id FROM owners_api_keys WHERE key_hash = $1 AND revoked = false`,
		apiKey,
	).Scan(&ownerId)

	if err != nil {
		utils.WriteError(w, http.StatusUnauthorized, "Invalid API Key", err.Error())
		return
	}

	var userpool models.UserPool
	row := db.GetDb().QueryRow(
		r.Context(),
		`INSERT INTO user_pools (owner_id, name, schema)
		VALUES ($1, $2, $3)
		RETURNING id, owner_id, name, schema, created_at, updated_at`,
		ownerId, input.Name, input.Schema,
	)

	if err := row.Scan(&userpool.ID, &userpool.OwnerID, &userpool.Name, &userpool.Schema, &userpool.CreatedAt, &userpool.UpdatedAt); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Failed to Create Userpool key", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(userpool)
}

// UpdateUserPool godoc
// @Summary      Update a user pool
// @Description  Updates the name or schema of an existing user pool identified by its ID. The owner is authenticated via X-API-KEY.
// @Tags         userpools
// @Accept       json
// @Produce      json
// @Param        X-API-KEY   header    string               true  "Owner API Key"
// @Param        userpoolId  path      string               true  "User Pool ID"
// @Param        userPool    body      models.UserPoolInput true  "Updated User Pool data"
// @Success      200  {object}  models.UserPool
// @Failure      400  {object}  models.ErrorResponse "Invalid request body"
// @Failure      401  {object}  models.ErrorResponse "Invalid API Key"
// @Failure      404  {object}  models.ErrorResponse "User pool not found"
// @Failure      500  {object}  models.ErrorResponse "Failed to update user pool"
// @Router       /api/v1/admin/user-pools/{userpoolId} [patch]
func updateUserpool(w http.ResponseWriter, r *http.Request, userpoolId string) {
	var input models.UserPoolInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request Body", err.Error())
		return
	}

	apiKey := r.Header.Get("X-API-KEY")
	var ownerId string
	err := db.GetDb().QueryRow(
		r.Context(),
		`SELECT owner_id FROM owners_api_keys WHERE key_hash = $1 AND revoked = false`,
		apiKey,
	).Scan(&ownerId)
	if err != nil {
		utils.WriteError(w, http.StatusUnauthorized, "Invalid API Key", err.Error())
		return
	}

	var userpool models.UserPool
	row := db.GetDb().QueryRow(
		r.Context(),
		`UPDATE user_pools
		 SET name = $1, schema = $2, updated_at = NOW()
		 WHERE id = $3 AND owner_id = $4
		 RETURNING id, owner_id, name, schema, created_at, updated_at`,
		input.Name, input.Schema, userpoolId, ownerId,
	)

	if err := row.Scan(&userpool.ID, &userpool.OwnerID, &userpool.Name, &userpool.Schema, &userpool.CreatedAt, &userpool.UpdatedAt); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Failed to update user pool", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(userpool)
}

// DeleteUserPool godoc
// @Summary      Delete a user pool
// @Description  Deletes an existing user pool identified by its ID. Only the owner with a valid API key can perform this action.
// @Tags         userpools
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
	err := db.GetDb().QueryRow(
		r.Context(),
		`SELECT owner_id FROM owners_api_keys WHERE key_hash = $1 AND revoked = false`,
		apiKey,
	).Scan(&ownerId)
	if err != nil {
		utils.WriteError(w, http.StatusUnauthorized, "Invalid API Key", err.Error())
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
