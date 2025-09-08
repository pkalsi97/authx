package models

import "time"

type CreateAdminRequest struct {
	Email        string `json:"email" validate:"required,email"`
	Name         string `json:"name" validate:"required"`
	Organization string `json:"organization" validate:"required"`
}

type CreateAdminResponse struct {
	Id        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

type CreateAPIKeyResponse struct {
	Key       string    `json:"key"`
	CreatedAt time.Time `json:"created_at"`
}

type DisableAPIKeyResponse struct {
	Id      string `json:"id"`
	Revoked bool   `json:"revoked"`
}

type CreateUserPoolRequest struct {
	Name   string                 `json:"name" validate:"required,min=3,max=50"`
	Schema map[string]interface{} `json:"schema" validate:"required"`
}

type CreateUserPoolResponse struct {
	Id        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

type UpdateUserPoolRequest struct {
	Name   string                 `json:"name" validate:"required,min=3,max=50"`
	Schema map[string]interface{} `json:"schema" validate:"required"`
}

type UpdateUserPoolResponse struct {
	Id string `json:"id"`
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

type PasswordLogin struct {
	Userpool string `json:"userpool"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type OtpLoginRequest struct {
	Userpool   string `json:"userpool"`
	Method     string `json:"method"`
	Credential string `json:"credential"`
}

type OtpLoginVerify struct {
	Id     string `json:"id"`
	Answer string `json:"answer"`
}

type OtpCacheData struct {
	Method string `json:"userpool"`
	Otp    string `json:"otp"`
	Tries  int    `json:"tries"`
}

type RefreshSession struct {
	Refreshtoken string `json:"refresh_token"`
	Idtoken      string `json:"id_token"`
}

type PasswordResetRequest struct {
	Userpool string `json:"userpool"`
	Email    string `json:"email"`
}

type PasswordResetVerify struct {
	Id       string `json:"id"`
	Answer   string `json:"answer"`
	Password string `json:"password"`
}

type PasswordResetCache struct {
	Id    string `json:"id"`
	Otp   string `json:"Otp"`
	Tries int    `json:"tries"`
}
