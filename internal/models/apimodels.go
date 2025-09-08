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

type SignupPhoneRequest struct {
	Userpool string `json:"userpool" validate:"required"`
	Phone    string `json:"phone" validate:"required"`
}

type SignupPhoneResponse struct {
	Id      string `json:"id"`
	Message string `json:"message"`
}

type SignupEmailRequest struct {
	ID       string `json:"id" validate:"required"`
	Email    string `json:"email" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type SignupEmailResponse struct {
	Id      string `json:"id"`
	Message string `json:"message"`
}

type UserSignupVerification struct {
	ID     string `json:"id" validate:"required"`
	Answer string `json:"answer" validate:"required"`
}

type UserSignupResponse struct {
	Id      string `json:"id"`
	Message string `json:"message"`
}

type SignupCompleteResponse struct {
	Id           string `json:"id"`
	UserId       string `json:"user_id"`
	Message      string `json:"message"`
	IdToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type PasswordLoginRequest struct {
	Userpool string `json:"userpool" validate:"required"`
	Email    string `json:"email" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type LoginResponse struct {
	Message      string `json:"message"`
	IdToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type OtpLoginRequest struct {
	Userpool   string `json:"userpool" validate:"required"`
	Method     string `json:"method" validate:"required"`
	Credential string `json:"credential" validate:"required"`
}

type OtpLoginResponse struct {
	Id      string `json:"id"`
	Message string `json:"message"`
}

type OtpLoginVerifyRequest struct {
	Id     string `json:"id" validate:"required"`
	Answer string `json:"answer" validate:"required"`
}

type OtpCacheData struct {
	Method string `json:"userpool"`
	Otp    string `json:"otp"`
	Tries  int    `json:"tries"`
}

type RefreshSessionRequest struct {
	Refreshtoken string `json:"refresh_token" validate:"required"`
	Idtoken      string `json:"id_token" validate:"required"`
}

type RefreshSessionResponse struct {
	Message     string `json:"message"`
	IdToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
}

type LogoutRequest struct {
	Refreshtoken string `json:"refresh_token" validate:"required"`
	Idtoken      string `json:"id_token" validate:"required"`
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

type PasswordResetRequest struct {
	Userpool string `json:"userpool" validate:"required"`
	Email    string `json:"email" validate:"required"`
}

type PasswordResetResponse struct {
	Id      string `json:"id"`
	Message string `json:"message"`
}

type PasswordResetVerifyRequest struct {
	Id       string `json:"id" validate:"required"`
	Answer   string `json:"answer" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type PasswordResetCache struct {
	Id    string `json:"id"`
	Otp   string `json:"Otp"`
	Tries int    `json:"tries"`
}
