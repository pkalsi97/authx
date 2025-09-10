package server

import (
	"net/http"

	"github.com/pkalsi97/authx/internal/handlers"
)

func SetUpRoutes() *http.ServeMux {
	mux := http.NewServeMux()
	registerAdminRoutes(mux)
	registerRbacRoutes(mux)
	registerAuthRoutes(mux)
	registerUserRoutes(mux)
	return mux
}

/*
-----------------------

	Admin Routes

-----------------------
*/
func registerAdminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/admin/owners/", handlers.OwnerRouter)
	mux.HandleFunc("/api/v1/admin/user-pools/", handlers.UserPoolRouter)
}

/*
-----------------------

	Rbac Routes

-----------------------
*/
func registerRbacRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/user-pools/", handlers.RbacRouter)
}

/*
-----------------------

	Auth Routes

-----------------------
*/
func registerAuthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/auth/login/password", handlers.PasswordLoginHandler)
	mux.HandleFunc("/api/v1/auth/login/request", handlers.LoginOtpRequestHandler)
	mux.HandleFunc("/api/v1/auth/login/verify", handlers.LoginOtpVerifyHandler)
	mux.HandleFunc("/api/v1/auth/session/refresh", handlers.SessionRefreshHandler)
	mux.HandleFunc("/api/v1/auth/logout", handlers.LogoutHandler)
	mux.HandleFunc("/api/v1/auth/signup/otp/phone/request", handlers.SignupPhoneOtpRequestHandler)
	mux.HandleFunc("/api/v1/auth/signup/otp/phone/verify", handlers.SignupPhoneOtpVerifyHandler)
	mux.HandleFunc("/api/v1/auth/signup/otp/email/request", handlers.SignupEmailOtpRequestHandler)
	mux.HandleFunc("/api/v1/auth/signup/complete", handlers.SignupVerifyAndCompleteHandler)
	mux.HandleFunc("/api/v1/auth/password/request", handlers.PasswordResetRequestHandler)
	mux.HandleFunc("/api/v1/auth/password/reset", handlers.PasswordResetCompleteHandler)
}

/*
-----------------------

	User Routes

-----------------------
*/
func registerUserRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/users/password/reset", handlers.UserPasswordResetHandler)
	mux.HandleFunc("/api/v1/users/credential/request", handlers.CredentialRequestHandler)
	mux.HandleFunc("/api/v1/users/credential/verify", handlers.CredentialVerifyHandler)
}
