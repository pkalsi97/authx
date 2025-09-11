package core

import (
	"context"
	"encoding/json"
	"log"

	"github.com/pkalsi97/authx/internal/db"
)

const (
	ActionUserSignup                  = "USER_SIGNUP"
	ActionUserLogin                   = "USER_LOGIN"
	ActionUserLogout                  = "USER_LOGOUT"
	ActionSessionRefresh              = "SESSION_REFRESH"
	ActionUserUpdateCredentialRequest = "USER_UPDATE_CREDENTIAL_REQUEST"
	ActionUserUpdateCredentialVerify  = "USER_UPDATE_CREDENTIAL_VERIFY"
	ActionPasswordResetReq            = "PASSWORD_RESET_REQUESTED"
	ActionPasswordChanged             = "PASSWORD_CHANGED"
	ActionRoleAssigned                = "ROLE_ASSIGNED"
	ActionRoleRevoked                 = "ROLE_REVOKED"
	ActionRoleCreated                 = "ROLE_CREATED"
	ActionRoleUpdated                 = "ROLE_UPDATED"
	ActionRoleDeleted                 = "ROLE_DELETED"
)

type AuditMetadata struct {
	IP        string `json:"ip,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Method    string `json:"method,omitempty"`
	Path      string `json:"path,omitempty"`
	Query     string `json:"query,omitempty"`
	Host      string `json:"host,omitempty"`
}

func CaptureAudit(ctx context.Context, userpoolId, actor, target, action string, metadata *AuditMetadata) {
	data, err := json.Marshal(metadata)
	if err != nil {
		log.Printf("Audit Error: failed to marshal metadata: %s", err.Error())
	}

	var id string
	query := `
        INSERT INTO audit_logs (user_pool_id, actor_id, action, target_id, metadata)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id
    `
	args := []any{userpoolId, actor, action, target, data}

	if err := db.QueryRowAndScan(ctx, query, args, &id); err != nil {
		resp := db.MapDbError(err)
		log.Printf("Audit Error: %s", resp.Message)
	}
}
