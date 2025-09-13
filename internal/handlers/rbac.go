package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/pkalsi97/authx/internal/core"
	"github.com/pkalsi97/authx/internal/db"
	"github.com/pkalsi97/authx/internal/models"
	"github.com/pkalsi97/authx/internal/router"
	"github.com/pkalsi97/authx/internal/utils"
)

var rbacRoutes = []router.Route{
	{
		Method:  http.MethodGet,
		Pattern: regexp.MustCompile(`^roles$`),
		Handler: func(w http.ResponseWriter, r *http.Request, _ []string) {
			getRolesData(w, r)
		},
	},
	{
		Method:  http.MethodPost,
		Pattern: regexp.MustCompile(`^pools/([^/]+)/roles$`),
		Handler: func(w http.ResponseWriter, r *http.Request, matches []string) {
			createRoles(w, r, matches[1])
		},
	},
	{
		Method:  http.MethodPatch,
		Pattern: regexp.MustCompile(`^roles/([^/]+)$`),
		Handler: func(w http.ResponseWriter, r *http.Request, matches []string) {
			roleID := matches[1]
			updateRoles(w, r, roleID)
		},
	},
	{
		Method:  http.MethodDelete,
		Pattern: regexp.MustCompile(`^roles/([^/]+)$`),
		Handler: func(w http.ResponseWriter, r *http.Request, matches []string) {
			roleID := matches[1]
			deleteRoles(w, r, roleID)
		},
	},
	{
		Method:  http.MethodPost,
		Pattern: regexp.MustCompile(`^users/([^/]+)/role/([^/]+)$`),
		Handler: func(w http.ResponseWriter, r *http.Request, matches []string) {
			userID := matches[1]
			roleID := matches[2]
			assignRole(w, r, userID, roleID)
		},
	},
	{
		Method:  http.MethodDelete,
		Pattern: regexp.MustCompile(`^users/([^/]+)/role/([^/]+)$`),
		Handler: func(w http.ResponseWriter, r *http.Request, matches []string) {
			userID := matches[1]
			roleID := matches[2]
			removeRole(w, r, userID, roleID)
		},
	},
	{
		Method:  http.MethodGet,
		Pattern: regexp.MustCompile(`^audit-logs$`),
		Handler: func(w http.ResponseWriter, r *http.Request, matches []string) {
			listAuditLogs(w, r)
		},
	},
}

func RbacRouter(w http.ResponseWriter, r *http.Request) {
	router.MatchAndServe(w, r, "/api/v1/rbac/", rbacRoutes)
}

// GetRolesData godoc
// @Summary      Retrieve roles for a user pool
// @Description  Returns all roles in a given user pool. Optionally, filter by user_id.
// @Tags         Rbac
// @Accept       json
// @Produce      json
// @Param        X-API-KEY  header    string                   true  "Owner API Key"
// @Param        pool_id  query     string  true   "User pool ID"
// @Param        user_id  query     string  false  "Optional user ID to filter roles assigned to a specific user"
// @Success      200      {array}   models.RolesRow   "List of roles"
// @Failure      400      {object}  models.ErrorResponse "Bad request (missing pool_id or invalid params)"
// @Failure      401      {object}  models.ErrorResponse "Unauthorized (missing or invalid API key)"
// @Failure      500      {object}  models.ErrorResponse "Server/database error"
// @Router       /api/v1/rbac/roles [get]
func getRolesData(w http.ResponseWriter, r *http.Request) {

	if err := utils.CheckHeaders(r, []string{"X-API-KEY"}); err != nil {
		utils.WriteError(w, http.StatusUnauthorized, "Missing Headers", err.Error())
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

	poolID := r.URL.Query().Get("pool_id")
	userID := r.URL.Query().Get("user_id")
	var rows pgx.Rows
	var err error

	if poolID == "" {
		utils.WriteError(w, http.StatusBadRequest, "Bad Request", "Invalid Query Params")
		return
	}

	query = `SELECT id, name, permissions FROM roles WHERE user_pool_id=$1`

	if userID != "" {
		query = `
				SELECT r.id, r.name, r.permissions
				FROM roles r
				JOIN user_roles ur ON ur.role_id = r.id
				JOIN users u ON u.id = ur.user_id
				WHERE u.id = $2
				AND u.user_pool_id = $1
				AND r.user_pool_id = $1;
    			`
		rows, err = db.GetDb().Query(r.Context(), query, poolID, userID)
	} else {
		rows, err = db.GetDb().Query(r.Context(), query, poolID)
	}

	if err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, resp.Status, "Database Error", resp.Message)
		return
	}

	defer rows.Close()

	var roles []models.RolesRow

	for rows.Next() {
		var role models.RolesRow
		if err := rows.Scan(&role.ID, &role.Name, &role.Permissions); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
			return
		}
		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	utils.WriteResponse(w, http.StatusOK, roles)
}

// CreateRoles godoc
// @Summary      Create a new role in a user pool
// @Description  Creates a new role with permissions in the specified user pool.
// @Tags         Rbac
// @Accept       json
// @Produce      json
// @Param        X-API-KEY  header    string                   true  "Owner API Key"
// @Param        pool_id  path     string  true   "User pool ID"
// @Param        input      body      models.CreateRoleRequest  true  "Role creation request"
// @Success      200        {object}  map[string]interface{}   "Role created successfully"
// @Failure      400        {object}  models.ErrorResponse    "Invalid input"
// @Failure      401        {object}  models.ErrorResponse    "Unauthorized (missing/invalid API key)"
// @Failure      500        {object}  models.ErrorResponse    "Server/database error"
// @Router       /api/v1/rbac/pools/{pool_id}/roles [post]
func createRoles(w http.ResponseWriter, r *http.Request, poolID string) {
	var roleId string

	if err := utils.CheckHeaders(r, []string{"X-API-KEY"}); err != nil {
		utils.WriteError(w, http.StatusUnauthorized, "Missing Headers", err.Error())
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

	input, err := utils.BindAndValidate[models.CreateRoleRequest](r, http.MethodPost)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request", err.Error())
		return
	}

	permissionsJSON, err := json.Marshal(input.Scope)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	query = `INSERT INTO roles (user_pool_id, name, permissions) VALUES ($1,$2,$3) RETURNING id`
	args = []any{poolID, input.Name, permissionsJSON}
	if err := db.QueryRowAndScan(r.Context(), query, args, &roleId); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, resp.Status, "Database Error", resp.Message)
		return
	}

	response := map[string]any{
		"role_id": roleId,
		"message": "Success",
	}

	utils.WriteResponse(w, http.StatusOK, response)
}

// UpdateRoles godoc
// @Summary      Update role permissions
// @Description  Updates the permissions of a role in the user pool.
// @Tags         Rbac
// @Accept       json
// @Produce      json
// @Param        X-API-KEY  header    string                  true  "Owner API Key"
// @Param        roleID     path      string                  true  "Role ID to update"
// @Param        input      body      models.UpdateRoleRequest  true  "Role update request"
// @Success      200        {object}  map[string]interface{} "Role updated successfully"
// @Failure      400        {object}  models.ErrorResponse   "Invalid input"
// @Failure      401        {object}  models.ErrorResponse   "Unauthorized (missing/invalid API key)"
// @Failure      500        {object}  models.ErrorResponse   "Server/database error"
// @Router       /api/v1/rbac/roles/{roleID} [patch]
func updateRoles(w http.ResponseWriter, r *http.Request, roleID string) {
	var roleName string

	if err := utils.CheckHeaders(r, []string{"X-API-KEY"}); err != nil {
		utils.WriteError(w, http.StatusUnauthorized, "Missing Headers", err.Error())
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

	input, err := utils.BindAndValidate[models.UpdateRoleRequest](r, http.MethodPatch)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request", err.Error())
		return
	}

	permissionsJSON, err := json.Marshal(input.Scope)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}
	var userpoolId string
	query = `UPDATE roles SET permissions=$1 WHERE id=$2 RETURNING name, user_pool_id`
	args = []any{permissionsJSON, roleID}
	if err := db.QueryRowAndScan(r.Context(), query, args, &roleName, &userpoolId); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, resp.Status, "Database Error", resp.Message)
		return
	}

	response := map[string]any{
		"role_name": roleName,
		"message":   "Success",
	}

	utils.WriteResponse(w, http.StatusOK, response)
}

// DeleteRoles godoc
// @Summary      Delete a role
// @Description  Deletes a specific role from the user pool.
// @Tags         Rbac
// @Accept       json
// @Produce      json
// @Param        X-API-KEY  header    string  true  "Owner API Key"
// @Param        role_id    path      string  true  "ID of the role to delete"
// @Success      200        {object}  map[string]interface{} "Role deleted successfully"
// @Failure      400        {object}  models.ErrorResponse   "Missing role ID"
// @Failure      401        {object}  models.ErrorResponse   "Unauthorized (missing/invalid API key)"
// @Failure      500        {object}  models.ErrorResponse   "Server/database error"
// @Router       /api/v1/rbac/roles/{role_id} [delete]
func deleteRoles(w http.ResponseWriter, r *http.Request, roleID string) {
	if err := utils.CheckHeaders(r, []string{"X-API-KEY"}); err != nil {
		utils.WriteError(w, http.StatusUnauthorized, "Missing Headers", err.Error())
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

	if roleID == "" {
		utils.WriteError(w, http.StatusBadRequest, "Missing path Param", "Role ID Not entered")
		return
	}

	var userpoolId string
	query = `DELETE FROM roles WHERE id = $1 RETURNING user_pool_id`
	args = []any{roleID}
	if err := db.QueryRowAndScan(r.Context(), query, args, &userpoolId); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, http.StatusUnauthorized, "Invalid API Key", resp.Message)
		return
	}

	utils.WriteResponse(w, http.StatusOK, map[string]any{"message": "Success"})
}

// AssignRole godoc
// @Summary      Assign a role to a user
// @Description  Assigns a specific role to a user.
// @Tags         Rbac
// @Accept       json
// @Produce      json
// @Param        X-API-KEY  header    string  true  "Owner API Key"
// @Param        role_id    path      string  true  "Role ID"
// @Param        user_id    path      string  true  "User ID to assign role to"
// @Success      200        {object}  map[string]interface{} "Role assigned successfully"
// @Failure      400        {object}  models.ErrorResponse   "Missing userID or roleID"
// @Failure      401        {object}  models.ErrorResponse   "Unauthorized (missing/invalid API key)"
// @Failure      500        {object}  models.ErrorResponse   "Server/database error"
// @Router       /api/v1/rbac/users/{user_id}/role/{role_id} [POST]
func assignRole(w http.ResponseWriter, r *http.Request, userID, roleID string) {
	var id string

	if err := utils.CheckHeaders(r, []string{"X-API-KEY"}); err != nil {
		utils.WriteError(w, http.StatusUnauthorized, "Missing Headers", err.Error())
		return
	}

	apiKey := r.Header.Get("X-API-KEY")

	var ownerID string
	query := `SELECT owner_id FROM owners_api_keys WHERE key_hash = $1 AND revoked = false`
	args := []any{apiKey}
	if err := db.QueryRowAndScan(r.Context(), query, args, &ownerID); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, http.StatusUnauthorized, "Invalid API Key", resp.Message)
		return
	}

	if roleID == "" || userID == "" {
		utils.WriteError(w, http.StatusBadRequest, "Missing path Param", "UserID/RoleID Not entered")
		return
	}

	userID = strings.TrimSpace(userID)
	ownerID = strings.TrimSpace(ownerID)
	var exists bool
	query = `
        SELECT EXISTS (
            SELECT 1
            FROM users u
            JOIN user_pools up ON u.user_pool_id = up.id
            WHERE u.id = $1
              AND up.owner_id = $2
        )
    `
	args = []any{userID, ownerID}
	if err := db.QueryRowAndScan(r.Context(), query, args, &exists); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, resp.Status, "Database Error", resp.Message)
		return
	}
	if !exists {
		utils.WriteError(w, http.StatusUnauthorized, "Unauthorised", "User Does not belong to any userpool owned by owner")
		return
	}

	var userpoolId string
	query = `SELECT user_pool_id FROM roles WHERE id=$1`
	args = []any{roleID}
	if err := db.QueryRowAndScan(r.Context(), query, args, &userpoolId); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, resp.Status, "Database Error", resp.Message)
		return
	}

	query = `INSERT INTO user_roles(user_id,role_id) VALUES ($1, $2) RETURNING id`
	args = []any{userID, roleID}
	if err := db.QueryRowAndScan(r.Context(), query, args, &id); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, resp.Status, "Database Error", resp.Message)
		return
	}

	core.CaptureAudit(r.Context(), userpoolId, userID, userID, core.ActionRoleAssigned, (*core.AuditMetadata)(core.ExtractRequestMetadata(r)))

	response := map[string]any{
		"link_id": id,
		"message": "Success",
	}

	utils.WriteResponse(w, http.StatusOK, response)
}

// RemoveRole godoc
// @Summary      Revoke a role from a user
// @Description  Removes a role assigned to a specific user.
// @Tags         Rbac
// @Accept       json
// @Produce      json
// @Param        X-API-KEY  header    string  true  "Owner API Key"
// @Param        role_id    path      string  true  "Role ID"
// @Param        user_id    path      string  true  "User ID"
// @Success      200        {object}  map[string]interface{} "Role revoked successfully"
// @Failure      400        {object}  models.ErrorResponse   "Missing userID or roleID"
// @Failure      401        {object}  models.ErrorResponse   "Unauthorized (missing/invalid API key)"
// @Failure      500        {object}  models.ErrorResponse   "Server/database error"
// @Router       /api/v1/rbac/users/{user_id}/role/{role_id} [DELETE]
func removeRole(w http.ResponseWriter, r *http.Request, userID, roleID string) {

	var id string

	if err := utils.CheckHeaders(r, []string{"X-API-KEY"}); err != nil {
		utils.WriteError(w, http.StatusUnauthorized, "Missing Headers", err.Error())
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

	if roleID == "" || userID == "" {
		utils.WriteError(w, http.StatusBadRequest, "Missing path Param", "UserID/RoleID Not entered")
		return
	}

	userID = strings.TrimSpace(userID)
	ownerId = strings.TrimSpace(ownerId)

	var exists bool
	query = `
        SELECT EXISTS (
            SELECT 1
            FROM users u
            JOIN user_pools up ON u.user_pool_id = up.id
            WHERE u.id = $1
              AND up.owner_id = $2
        )
    `
	args = []any{userID, ownerId}
	if err := db.QueryRowAndScan(r.Context(), query, args, &exists); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, resp.Status, "Database Error", resp.Message)
		return
	}
	if !exists {
		utils.WriteError(w, http.StatusUnauthorized, "Unauthorised", "User Does not belong to any userpool owned by owner")
		return
	}

	query = `DELETE FROM user_roles WHERE user_id=$1 AND role_id=$2 RETURNING id`
	args = []any{userID, roleID}
	if err := db.QueryRowAndScan(r.Context(), query, args, &id); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, resp.Status, "Database Error", resp.Message)
		return
	}

	var userpoolId string
	query = `SELECT user_pool_id FROM roles WHERE id=$1`
	args = []any{roleID}
	if err := db.QueryRowAndScan(r.Context(), query, args, &userpoolId); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, resp.Status, "Database Error", resp.Message)
		return
	}

	response := map[string]any{
		"link_id": id,
		"message": "Deleted",
	}
	core.CaptureAudit(r.Context(), userpoolId, userID, userID, core.ActionRoleRevoked, (*core.AuditMetadata)(core.ExtractRequestMetadata(r)))

	utils.WriteResponse(w, http.StatusOK, response)
}

// ListAuditLogs godoc
// @Summary      Get audit logs
// @Description  Returns audit logs for a given user pool. Can filter by actor_id, action, and target_id.
// @Tags         Rbac
// @Accept       json
// @Produce      json
// @Param        X-API-KEY  header    string  true  "Owner API Key"
// @Param        pool_id   path      string  true   "User pool ID"
// @Param        actor_id  query     string  false  "Filter by actor ID"
// @Param        action    query     string  false  "Filter by action"
// @Param        target_id query     string  false  "Filter by target ID"
// @Success      200       {array}   models.AuditLog  "List of audit logs"
// @Failure      400       {object}  models.ErrorResponse  "Missing pool_id"
// @Failure      500       {object}  models.ErrorResponse  "Server/database error"
// @Router       /api/v1/rbac/audit-logs [get]
func listAuditLogs(w http.ResponseWriter, r *http.Request) {

	if err := utils.CheckHeaders(r, []string{"X-API-KEY"}); err != nil {
		utils.WriteError(w, http.StatusUnauthorized, "Missing Headers", err.Error())
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

	poolID := r.URL.Query().Get("pool_id")
	if poolID == "" {
		http.Error(w, "pool_id is required", http.StatusBadRequest)
		return
	}

	actorID := r.URL.Query().Get("actor_id")
	action := r.URL.Query().Get("action")
	targetID := r.URL.Query().Get("target_id")

	query = "SELECT id, user_pool_id, actor_id, action, target_id, metadata, created_at FROM audit_logs WHERE user_pool_id = $1"
	args = []interface{}{poolID}
	argIndex := 2

	if actorID != "" {
		query += fmt.Sprintf(" AND actor_id = $%d", argIndex)
		args = append(args, actorID)
		argIndex++
	}
	if action != "" {
		query += fmt.Sprintf(" AND action = $%d", argIndex)
		args = append(args, action)
		argIndex++
	}
	if targetID != "" {
		query += fmt.Sprintf(" AND target_id = $%d", argIndex)
		args = append(args, targetID)
		argIndex++
	}

	rows, err := db.GetDb().Query(r.Context(), query, args...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	logs := []models.AuditLog{}
	for rows.Next() {
		var log models.AuditLog
		var metadataBytes []byte

		err := rows.Scan(&log.ID, &log.UserPoolID, &log.ActorID, &log.Action, &log.TargetID, &metadataBytes, &log.CreatedAt)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(metadataBytes) > 0 {
			err = json.Unmarshal(metadataBytes, &log.Metadata)
			if err != nil {
				http.Error(w, "failed to parse metadata: "+err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			log.Metadata = map[string]interface{}{}
		}

		logs = append(logs, log)
	}

	utils.WriteResponse(w, http.StatusOK, logs)
}
