package models

import (
	"time"
)

type ErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}

type OwnerInput struct {
	Email        string `json:"email"`
	Name         string `json:"name"`
	Organization string `json:"organization"`
}

type UserPoolInput struct {
	Name   string                 `json:"name"`
	Schema map[string]interface{} `json:"schema,omitempty"`
}
type Owner struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	Name         string    `json:"name"`
	Organization string    `json:"organization"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type OwnerAPIKey struct {
	ID        string    `json:"id"`
	OwnerID   string    `json:"owner_id"`
	KeyHash   string    `json:"key_hash"`
	CreatedAt time.Time `json:"created_at"`
	Revoked   bool      `json:"revoked"`
}

type UserPool struct {
	ID        string                 `json:"id"`
	OwnerID   string                 `json:"owner_id"`
	Name      string                 `json:"name"`
	Schema    map[string]interface{} `json:"schema"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

type User struct {
	ID            string                 `json:"id"`
	UserPoolID    string                 `json:"user_pool_id"`
	Email         string                 `json:"email"`
	EmailVerified bool                   `json:"email_verified"`
	Phone         string                 `json:"phone"`
	PhoneVerified bool                   `json:"phone_verified"`
	PasswordHash  string                 `json:"-"`
	Metadata      map[string]interface{} `json:"metadata"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
}

type Role struct {
	ID          string                 `json:"id"`
	UserPoolID  string                 `json:"user_pool_id"`
	Name        string                 `json:"name"`
	Permissions map[string]interface{} `json:"permissions"`
}

type UserRole struct {
	ID     string `json:"id"`
	UserID string `json:"user_id"`
	RoleID string `json:"role_id"`
}

type RefreshToken struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	TokenHash string    `json:"-"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
}

type AuditLog struct {
	ID         string                 `json:"id"`
	UserPoolID string                 `json:"user_pool_id"`
	ActorID    string                 `json:"actor_id,omitempty"`
	Action     string                 `json:"action"`
	TargetID   string                 `json:"target_id,omitempty"`
	Metadata   map[string]interface{} `json:"metadata"`
	CreatedAt  time.Time              `json:"created_at"`
}

type UserSignupData struct {
	ID            string `json:"id"`
	Phone         string `json:"phone"`
	PhoneVerified bool   `json:"phone_verified"`
	PhoneTries    int    `json:"phone_tries"`
	PhoneOtp      string `json:"phone_otp"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	EmailTries    int    `json:"email_tries"`
	EmailOtp      string `json:"email_otp"`
	Userpool      string `json:"userpool"`
	Password      string `json:"password"`
}

type UserSignupVerification struct {
	ID     string `json:"id"`
	Answer string `json:"answer"`
}

type SignupComplete struct {
	ID       string `json:"id"`
	Password string `json:"password"`
}
