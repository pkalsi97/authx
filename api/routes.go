package api

import (
	"net/http"

	"github.com/pkalsi97/authx/internal/admin"
	"github.com/pkalsi97/authx/internal/auth"
	"github.com/pkalsi97/authx/internal/rbac"
	"github.com/pkalsi97/authx/internal/user"
)

func SetUpRoutes() *http.ServeMux {
	mux := http.NewServeMux()
	registerAdminRoutes(mux)
	registerRbacRoutes(mux)
	registerAuthRoutes(mux)
	registerOauthRoutes(mux)
	registerUserRoutes(mux)
	return mux
}

/*
-----------------------

	Admin Routes

-----------------------
*/
func registerAdminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/admin/owners/", admin.OwnerRouter)
	mux.HandleFunc("/api/v1/admin/user-pools/", admin.UserPoolRouter)
}

/*
-----------------------

	Rbac Routes

-----------------------
*/
func registerRbacRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/user-pools/", rbac.RbacRouter)
}

/*
-----------------------

	Auth Routes

-----------------------
*/
func registerAuthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/auth/login/password", auth.PasswordLoginHandler)
	mux.HandleFunc("/api/v1/auth/login/request", auth.LoginOtpRequestHandler)
	mux.HandleFunc("/api/v1/auth/login/verify", auth.LoginOtpVerifyHandler)
	mux.HandleFunc("/api/v1/auth/session/refresh", auth.SessionRefreshHandler)
	mux.HandleFunc("/api/v1/auth/logout", auth.LogoutHandler)
	mux.HandleFunc("/api/v1/auth/signup/otp/request", auth.SignupOtpRequestHandler)
	mux.HandleFunc("/api/v1/auth/signup/otp/verify", auth.SignupOtpVerifyHandler)
	mux.HandleFunc("/api/v1/auth/signup/complete", auth.SignupCompleteHandler)
	mux.HandleFunc("/api/v1/auth/password/request", auth.PasswordResetRequestHandler)
	mux.HandleFunc("/api/v1/auth/password/reset", auth.PasswordResetCompleteHandler)
}

/*
---------------------

	OAuth Routes

-----------------------
*/
func registerOauthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/auth/oauth/google/redirect", auth.GoogleOauthRedirectHandler)
	mux.HandleFunc("/api/v1/auth/oauth/google/callback", auth.GooleOauthCallbackHandler)
	mux.HandleFunc("/api/v1/auth/oauth/git/redirect", auth.GitOauthRedirectHandler)
	mux.HandleFunc("/api/v1/auth/oauth/git/callback", auth.GitOauthCallbackHandler)
}

/*
-----------------------

	User Routes

-----------------------
*/
func registerUserRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/users/password/reset", user.UserPasswordResetHandler)
	mux.HandleFunc("/api/v1/users/credential/request", user.CredentialRequestHandler)
	mux.HandleFunc("/api/v1/users/credential/verify", user.CredentialVerifyHandler)
}
