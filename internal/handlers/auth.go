package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/pkalsi97/authx/internal/core"
	"github.com/pkalsi97/authx/internal/db"
	"github.com/pkalsi97/authx/internal/models"
	"github.com/pkalsi97/authx/internal/utils"
)

// SignupPhoneOtpRequestHandler godoc
// @Summary      Request OTP for phone signup
// @Description  Validates phone and user pool, generates an OTP, stores it in Redis, and sends it to the user's phone.
// @Tags         Signup
// @Accept       json
// @Produce      json
// @Param        input  body      models.SignupPhoneRequest   true  "Signup phone request data including phone and userpool ID"
// @Success      200    {object}  models.SignupPhoneResponse  "OTP sent successfully"
// @Failure      400    {object}  models.ErrorResponse        "Missing/Invalid essential inputs or validation error"
// @Failure      409    {object}  models.ErrorResponse        "Phone number already registered"
// @Failure      500    {object}  models.ErrorResponse        "Database or server error"
// @Router       /api/v1/auth/signup/phone/request [post]
func SignupPhoneOtpRequestHandler(w http.ResponseWriter, r *http.Request) {
	var user models.UserSignupData

	input, err := utils.BindAndValidate[models.SignupPhoneRequest](r, http.MethodPost)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request", err.Error())
		return
	}

	var cleanPhone string
	var valid bool
	if cleanPhone, valid = utils.IsValidPhone(input.Phone); !valid {
		utils.WriteError(w, http.StatusBadRequest, "Missing/Invalid Essential Inputs", "")
		return
	}

	var userPoolExists bool
	var phoneExists bool
	query := `SELECT EXISTS(SELECT 1 FROM user_pools WHERE id=$1)`
	args := []any{input.Userpool}
	if err := db.QueryRowAndScan(r.Context(), query, args, &userPoolExists); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, resp.Status, "Database error", resp.Message)
		return
	}

	query = `SELECT EXISTS(SELECT 1 FROM users WHERE phone=$1)`
	args = []any{input.Phone}
	if err := db.QueryRowAndScan(r.Context(), query, args, &phoneExists); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, resp.Status, "Database error", resp.Message)
		return
	}

	otp, err := utils.GenerateOtp()
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Generate OTP", err.Error())
		return
	}
	user.Phone, user.Userpool, user.PhoneOtp, user.PhoneTries, user.EmailTries, user.ID = cleanPhone, input.Userpool, otp, 3, 3, uuid.NewString()

	if err := db.RedisSet(r.Context(), user.ID, &user); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Generate OTP", err.Error())
		return
	}

	if err := utils.SendOtp(otp); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Send OTP", err.Error())
		return
	}

	response := &models.SignupPhoneResponse{
		Id:      user.ID,
		Message: "OTP sent successfully",
	}

	utils.WriteResponse(w, http.StatusOK, response)
}

// SignupEmailOtpRequestHandler godoc
// @Summary      Request OTP for email signup
// @Description  Validates signup session ID, email, and password, generates an OTP, stores it in Redis, and sends it to the user's email.
// @Tags         Signup
// @Accept       json
// @Produce      json
// @Param        input  body      models.SignupEmailRequest   true  "Signup email request data including signup session ID, email, and password"
// @Success      200    {object}  models.SignupEmailResponse  "OTP sent successfully"
// @Failure      400    {object}  models.ErrorResponse        "Invalid request body, missing fields, or invalid signup session ID"
// @Failure      409    {object}  models.ErrorResponse        "Email already registered"
// @Failure      500    {object}  models.ErrorResponse        "Database or server error"
// @Router       /api/v1/auth/signup/email/request [post]
func SignupEmailOtpRequestHandler(w http.ResponseWriter, r *http.Request) {
	var user *models.UserSignupData

	input, err := utils.BindAndValidate[models.SignupEmailRequest](r, http.MethodPost)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request", err.Error())
		return
	}

	if !utils.IsValidEmail(input.Email) {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Email", "Please enter the correct email")
		return
	}

	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)`
	args := []any{input.Email}
	if err := db.QueryRowAndScan(r.Context(), query, args, &exists); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, resp.Status, "Database error", resp.Message)
		return
	}

	otp, err := utils.GenerateOtp()
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Generate OTP", err.Error())
		return
	}

	user, err = db.RedisGet[models.UserSignupData](r.Context(), input.ID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Generate OTP", err.Error())
		return
	}

	if user == nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Signup ID", "No signup session found for this ID")
		return
	}

	hashedPassword, err := utils.CreateHash(input.Password)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Generate OTP", err.Error())
		return
	}

	user.Email, user.EmailOtp, user.Password = input.Email, otp, hashedPassword

	if err := db.RedisSet(r.Context(), input.ID, user); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Generate OTP", err.Error())
		return
	}

	if err := utils.SendOtp(otp); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Send OTP", err.Error())
		return
	}

	response := &models.SignupEmailResponse{
		Id:      user.ID,
		Message: "OTP sent successfully",
	}
	utils.WriteResponse(w, http.StatusOK, response)
}

// SignupPhoneOtpVerifyHandler godoc
// @Summary Verify phone signup OTP
// @Description Verifies the phone OTP and marks the phone as verified in the signup session.
// @Tags Signup
// @Accept json
// @Produce json
// @Param input body models.UserSignupVerification true "Phone OTP verification request"
// @Success 200 {object} models.UserSignupResponse "Phone verified successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid signup ID or wrong OTP"
// @Failure 500 {object} models.ErrorResponse "Server error"
// @Router /api/v1/auth/signup/phone/verify [post]
func SignupPhoneOtpVerifyHandler(w http.ResponseWriter, r *http.Request) {
	var user *models.UserSignupData

	input, err := utils.BindAndValidate[models.UserSignupVerification](r, http.MethodPost)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request", err.Error())
		return
	}

	user, err = db.RedisGet[models.UserSignupData](r.Context(), input.ID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Verify OTP", err.Error())
		return
	}

	if user == nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Signup ID", "No signup session found for this ID")
		return
	}

	answer := input.Answer
	otp := user.PhoneOtp

	if answer != otp {
		user.PhoneTries--
		if user.PhoneTries <= 0 {
			utils.WriteError(w, http.StatusInternalServerError, "Sign-Up Failed", "Retry attempts exhausted")
			db.RedisDel(r.Context(), input.ID)
			return
		}
		message := fmt.Sprintf("Attempts left %d", user.PhoneTries)
		utils.WriteError(w, http.StatusBadRequest, "Please enter the right OTP", message)
		if err := db.RedisSet(r.Context(), input.ID, user); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, "Unable to Generate OTP", err.Error())
			return
		}
		return
	} else {
		user.PhoneVerified = true
		if err := db.RedisSet(r.Context(), input.ID, user); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, "Unable to Generate OTP", err.Error())
			return
		}
	}
	response := &models.UserSignupResponse{
		Id:      user.ID,
		Message: "OTP Verified successfully",
	}
	utils.WriteResponse(w, http.StatusOK, response)
}

// SignupVerifyAndCompleteHandler godoc
// @Summary Complete signup with email OTP verification
// @Description Verifies the OTP sent to the user's email during signup, checks phone verification, creates the user in the database, assigns default roles, and returns JWT tokens for login.
// @Tags Signup
// @Accept json
// @Produce json
// @Param input body models.UserSignupVerification true "Signup verification request including signup session ID and OTP"
// @Success 200 {object} models.SignupCompleteResponse "Signup completed successfully with ID, user ID, and tokens"
// @Failure 400 {object} models.ErrorResponse "Invalid signup ID, wrong OTP, or input validation error"
// @Failure 406 {object} models.ErrorResponse "Phone not verified, cannot complete signup"
// @Failure 409 {object} models.ErrorResponse "Email or phone already verified / user already exists"
// @Failure 500 {object} models.ErrorResponse "Server error, Redis error, or database failure"
// @Router /api/v1/auth/signup/complete [post]
func SignupVerifyAndCompleteHandler(w http.ResponseWriter, r *http.Request) {
	var user *models.UserSignupData

	input, err := utils.BindAndValidate[models.UserSignupVerification](r, http.MethodPost)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request", err.Error())
		return
	}

	user, err = db.RedisGet[models.UserSignupData](r.Context(), input.ID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Verify OTP", err.Error())
		return
	}
	if user == nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Signup ID", "No signup session found for this ID")
		return
	}

	answer := input.Answer
	otp := user.EmailOtp

	if answer != otp {
		user.EmailTries--
		if user.EmailTries <= 0 {
			utils.WriteError(w, http.StatusInternalServerError, "Sign-Up Failed", "Retry attempts exhausted")
			db.RedisDel(r.Context(), input.ID)
			return
		}
		message := fmt.Sprintf("Attempts left %d", user.EmailTries)
		utils.WriteError(w, http.StatusBadRequest, "Please enter the right OTP", message)
		if err := db.RedisSet(r.Context(), input.ID, user); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, "Unable to Generate OTP", err.Error())
			return
		}
		return
	}

	user.EmailVerified = true
	if err := db.RedisSet(r.Context(), input.ID, user); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Generate OTP", err.Error())
		return
	}

	if !user.PhoneVerified {
		utils.WriteError(w, http.StatusNotAcceptable, "Phone Not Verified", "Either Phone/Email not Verified")
		return
	}

	userpool := user.Userpool
	var schema map[string]interface{}
	var schemaBytes []byte
	var userId string
	var tokenID string

	query := `SELECT schema FROM user_pools WHERE id=$1 `
	args := []any{userpool}
	if err := db.QueryRowAndScan(r.Context(), query, args, &schemaBytes); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Complete Signup", resp.Message)
		return
	}

	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Complete Signup", err.Error())
		return
	}

	metadataBytes, err := json.Marshal(schema)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Complete Signup", err.Error())
		return
	}

	query = `INSERT INTO users(user_pool_id, email, email_verified, phone, phone_verified, password_hash, metadata)
    			VALUES($1,$2,$3,$4,$5,$6,$7)
    			RETURNING id`
	args = []any{userpool, user.Email, user.EmailVerified, user.Phone, user.PhoneVerified, user.Password, metadataBytes}
	if err := db.QueryRowAndScan(r.Context(), query, args, &userId); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Complete Signup", resp.Message)
		return
	}
	var roleId string
	var permissionsJSON []byte
	var permissions []string

	query = `SELECT id, permissions From roles WHERE user_pool_id=$1 AND NAME='user'`
	args = []any{userpool}

	if err := db.QueryRowAndScan(r.Context(), query, args, &roleId, &permissionsJSON); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Complete Signup", resp.Message)
		return
	}

	if err := json.Unmarshal(permissionsJSON, &permissions); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Complete Signup", err.Error())
		return
	}

	var userRoleID string
	query = `INSERT INTO user_roles(user_id,role_id) VALUES ($1, $2) RETURNING id`
	args = []any{userId, roleId}
	if err := db.QueryRowAndScan(r.Context(), query, args, &userRoleID); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Complete Signup", resp.Message)
		return
	}

	tokens, err := utils.GenerateTokens(userId, user.Email, user.Phone, userpool, permissions, []string{"user"})
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Signup complete but unable to login", err.Error())
		return
	}

	if err := db.RedisDel(r.Context(), input.ID); err != nil {
		log.Printf("warning: failed to cleanup redis key for id %s: %v", input.ID, err)
	}

	hashedToken, err := utils.CreateHash(tokens.RefreshToken)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Signup complete but unable to login", err.Error())
		return
	}

	query = `INSERT INTO refresh_tokens (user_id, token_hash,expires_at)
			VALUES($1,$2,$3)
			RETURNING id`
	args = []any{userId, hashedToken, time.Now().Add(365 * time.Minute)}
	if err := db.QueryRowAndScan(r.Context(), query, args, &tokenID); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Complete Signup", resp.Message)
		return
	}

	core.CaptureAudit(r.Context(), userpool, userId, userId, core.ActionUserSignup, (*core.AuditMetadata)(core.ExtractRequestMetadata(r)))

	response := &models.SignupCompleteResponse{
		Id:           input.ID,
		UserId:       userId,
		Message:      "Account Creation Succesful",
		IdToken:      tokens.IDToken,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}

	utils.WriteResponse(w, http.StatusOK, response)
}

// PasswordLoginHandler godoc
// @Summary      Login with email and password
// @Description  Authenticates a user using email, password, and user pool. Returns ID token, access token, and refresh token on successful login.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        input  body      models.PasswordLoginRequest  true  "Password login request including email, password, and user pool ID"
// @Success      200    {object}  models.LoginResponse         "Login successful with tokens"
// @Failure      400    {object}  models.ErrorResponse         "Invalid request body or validation error"
// @Failure      401    {object}  models.ErrorResponse         "Incorrect password"
// @Failure      404    {object}  models.ErrorResponse         "User not found"
// @Failure      500    {object}  models.ErrorResponse         "Server or database error"
// @Router       /api/v1/auth/login/password [post]
func PasswordLoginHandler(w http.ResponseWriter, r *http.Request) {

	input, err := utils.BindAndValidate[models.PasswordLoginRequest](r, http.MethodPost)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request", err.Error())
		return
	}

	var id, phone, password_hash string

	query := `SELECT id, phone, password_hash FROM users WHERE email=$1 AND user_pool_id=$2`
	args := []any{input.Email, input.Userpool}
	if err := db.QueryRowAndScan(r.Context(), query, args, &id, &phone, &password_hash); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Complete Login", resp.Message)
		return
	}

	match := utils.CompareHash(password_hash, input.Password)
	if !match {
		utils.WriteError(w, http.StatusUnauthorized, "Incorrect Password", "Plase enter the correct password")
		return
	}

	permissions, roles, err := db.GetUserRolesAndPermissions(r.Context(), id)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Login", err.Error())
		return
	}

	tokens, err := utils.GenerateTokens(id, input.Email, phone, input.Userpool, permissions, roles)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Login", err.Error())
		return
	}

	query = `UPDATE refresh_tokens SET revoked = true WHERE user_id = $1 AND revoked = false`
	_, err = db.GetDb().Exec(r.Context(), query, id)
	if err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Complete Login", resp.Message)
		return
	}

	hashedToken, err := utils.CreateHash(tokens.RefreshToken)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Login Failed", err.Error())
		return
	}

	var tokenID string
	query = `INSERT INTO refresh_tokens (user_id, token_hash,expires_at)
			VALUES($1,$2,$3)
			RETURNING id`
	args = []any{id, hashedToken, time.Now().Add(365 * time.Minute)}
	if err := db.QueryRowAndScan(r.Context(), query, args, &tokenID); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Complete Login", resp.Message)
		return
	}

	core.CaptureAudit(r.Context(), input.Userpool, id, id, core.ActionUserLogin, (*core.AuditMetadata)(core.ExtractRequestMetadata(r)))

	response := &models.LoginResponse{
		Message:      "Login Successful",
		IdToken:      tokens.IDToken,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}

	utils.WriteResponse(w, http.StatusOK, response)
}

// LoginOtpRequestHandler godoc
// @Summary      Request OTP for login
// @Description  Starts OTP-based login by sending OTP to email or phone (based on method).
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        input  body      models.OtpLoginRequest   true  "Login OTP request"
// @Success      200    {object}  models.OtpLoginResponse  "OTP sent successfully"
// @Failure      400    {object}  models.ErrorResponse     "Invalid request body or method"
// @Failure      404    {object}  models.ErrorResponse     "User not found"
// @Failure      500    {object}  models.ErrorResponse     "Server or database error"
// @Router       /api/v1/auth/login/request [post]
func LoginOtpRequestHandler(w http.ResponseWriter, r *http.Request) {

	input, err := utils.BindAndValidate[models.OtpLoginRequest](r, http.MethodPost)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request", err.Error())
		return
	}

	var query, userid, email, phone string

	switch input.Method {
	case "phone":
		phone = input.Credential
		query = `SELECT id, email FROM users WHERE phone=$1 AND user_pool_id=$2`
		args := []any{phone, input.Userpool}
		if err := db.QueryRowAndScan(r.Context(), query, args, &userid, &email); err != nil {
			resp := db.MapDbError(err)
			utils.WriteError(w, http.StatusInternalServerError, "Unable to Complete Login", resp.Message)
			return
		}
	case "email":
		email = input.Credential
		query = `SELECT id, phone FROM users WHERE email=$1 AND user_pool_id=$2`
		args := []any{email, input.Userpool}
		if err := db.QueryRowAndScan(r.Context(), query, args, &userid, &phone); err != nil {
			resp := db.MapDbError(err)
			utils.WriteError(w, http.StatusInternalServerError, "Unable to Complete Login", resp.Message)
			return
		}
	default:
		utils.WriteError(w, http.StatusBadRequest, "Invalid Method", "use phone/email")
		return
	}

	otp, err := utils.GenerateOtp()
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Login Request Failed", err.Error())
		return
	}

	data := &models.OtpCacheData{
		Method:   input.Method,
		Otp:      otp,
		Tries:    3,
		UserId:   userid,
		Email:    email,
		Phone:    phone,
		Userpool: input.Userpool,
	}
	cacheid := uuid.NewString()

	if err := db.RedisSet(r.Context(), cacheid, data); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Login Request Failed", err.Error())
		return
	}

	if err := utils.SendOtp(otp); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Send OTP", err.Error())
		return
	}

	response := &models.OtpLoginResponse{
		Id:      cacheid,
		Message: "OTP sent successfully",
	}

	utils.WriteResponse(w, http.StatusOK, response)
}

// LoginOtpVerifyHandler godoc
// @Summary      Verify OTP for login
// @Description  Verifies the OTP provided by the user for OTP-based login. If valid, generates new ID, access, and refresh tokens, revokes previous refresh tokens, and returns the tokens.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        input  body      models.OtpLoginVerifyRequest  true  "OTP verification request containing cache ID and OTP answer"
// @Success      200    {object}  models.LoginResponse          "Login successful with new tokens"
// @Failure      400    {object}  models.ErrorResponse          "Invalid request body, wrong OTP, or validation error"
// @Failure      404    {object}  models.ErrorResponse          "OTP session not found or expired"
// @Failure      500    {object}  models.ErrorResponse          "Server, database, or token generation error"
// @Router       /api/v1/auth/login/verify [post]
func LoginOtpVerifyHandler(w http.ResponseWriter, r *http.Request) {

	input, err := utils.BindAndValidate[models.OtpLoginVerifyRequest](r, http.MethodPost)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request", err.Error())
		return
	}

	cache, err := db.RedisGet[models.OtpCacheData](r.Context(), input.Id)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to verify OTP", err.Error())
		return
	}
	if cache == nil {
		utils.WriteError(w, http.StatusNotFound, "OTP session not found or expired", "")
		return
	}

	if input.Answer != cache.Otp {
		cache.Tries--
		if cache.Tries <= 0 {
			utils.WriteError(w, http.StatusInternalServerError, "Login Failed, To many wrong attempt", "Tries Left = 0")
			db.RedisDel(r.Context(), input.Id)
			return
		}
		message := fmt.Sprintf("Attempts left %d", cache.Tries)
		utils.WriteError(w, http.StatusBadRequest, "Please enter the right Otp", message)
		if err := db.RedisSet(r.Context(), input.Id, cache); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, "Unable to Generate OTP", err.Error())
			return
		}
		return
	}

	email, phone, userpool := cache.Email, cache.Phone, cache.Userpool
	permissions, roles, err := db.GetUserRolesAndPermissions(r.Context(), cache.UserId)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Login", err.Error())
		return
	}

	tokens, err := utils.GenerateTokens(cache.UserId, email, phone, userpool, permissions, roles)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Login Failed", err.Error())
		return
	}

	query := `UPDATE refresh_tokens SET revoked = true WHERE user_id = $1 AND revoked = false`
	_, err = db.GetDb().Exec(r.Context(), query, cache.UserId)
	if err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Complete Login", resp.Message)
		return
	}

	hashedToken, err := utils.CreateHash(tokens.RefreshToken)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Login Failed", err.Error())
		return
	}

	var tokenID string
	query = `INSERT INTO refresh_tokens (user_id, token_hash,expires_at)
			VALUES($1,$2,$3)
			RETURNING id`
	args := []any{cache.UserId, hashedToken, time.Now().Add(365 * time.Minute)}
	if err := db.QueryRowAndScan(r.Context(), query, args, &tokenID); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Complete Login", resp.Message)
		return
	}

	if err = db.RedisDel(r.Context(), input.Id); err != nil {
		log.Printf("Unable to delete Key/Value in redis %s", err.Error())
	}

	core.CaptureAudit(r.Context(), userpool, cache.UserId, cache.UserId, core.ActionUserSignup, (*core.AuditMetadata)(core.ExtractRequestMetadata(r)))

	response := &models.LoginResponse{
		Message:      "Login Successful",
		IdToken:      tokens.IDToken,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}

	utils.WriteResponse(w, http.StatusOK, response)
}

// SessionRefreshHandler godoc
// @Summary      Refresh session tokens
// @Description  Generates new ID and access tokens using a valid refresh token and ID token. Ensures the refresh token is valid and not revoked.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        input  body      models.RefreshSessionRequest  true  "Session refresh request containing ID token and refresh token"
// @Success      200    {object}  models.RefreshSessionResponse "New ID and access tokens returned"
// @Failure      400    {object}  models.ErrorResponse         "Invalid request body or validation error"
// @Failure      401    {object}  models.ErrorResponse         "Invalid or mismatched refresh token"
// @Failure      404    {object}  models.ErrorResponse         "User not found"
// @Failure      500    {object}  models.ErrorResponse         "Server or database error"
// @Router       /api/v1/auth/session/refresh [post]
func SessionRefreshHandler(w http.ResponseWriter, r *http.Request) {

	token, err := utils.BindAndValidate[models.RefreshSessionRequest](r, http.MethodPost)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request", err.Error())
		return
	}

	userId, userpool, err := utils.ExtractUserIDFromIDToken(token.Idtoken)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Session Refresh Failed", err.Error())
		return
	}

	var tokenHash string
	query := `SELECT token_hash FROM refresh_tokens WHERE user_id=$1 AND revoked=false`
	args := []any{userId}
	if err := db.QueryRowAndScan(r.Context(), query, args, &tokenHash); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Complete Login", resp.Message)
		return
	}

	if !utils.CompareHash(tokenHash, token.Refreshtoken) {
		utils.WriteError(w, http.StatusUnauthorized, "Session Refresh Failed", "Please Provide Correct Refresh Token")
		return
	}

	var email, phone string
	query = `SELECT email, phone FROM users WHERE id=$1`
	args = []any{userId}
	if err := db.QueryRowAndScan(r.Context(), query, args, &email, &phone); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Complete Login", resp.Message)
		return
	}

	permissions, roles, err := db.GetUserRolesAndPermissions(r.Context(), userId)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Database error", "code x")
		return
	}

	newTokens, err := utils.RefreshTokens(userId, email, phone, userpool, permissions, roles)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Login Failed", err.Error())
		return
	}
	core.CaptureAudit(r.Context(), userpool, userId, userId, core.ActionSessionRefresh, (*core.AuditMetadata)(core.ExtractRequestMetadata(r)))
	response := &models.RefreshSessionResponse{
		Message:     "Session Refresh successfully",
		IdToken:     newTokens.IDToken,
		AccessToken: newTokens.AccessToken,
	}

	utils.WriteResponse(w, http.StatusOK, response)
}

// LogoutHandler godoc
// @Summary      Logout user
// @Description  Logs out the user by revoking all refresh tokens associated with their account.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        input  body      models.LogoutRequest  true  "Logout request containing ID token"
// @Success      200    {object}  map[string]string     "Logout successful"
// @Failure      400    {object}  models.ErrorResponse  "Invalid request body or validation error"
// @Failure      403    {object}  models.ErrorResponse  "Unable to extract user ID from token"
// @Failure      500    {object}  models.ErrorResponse  "Database error while revoking tokens"
// @Router       /api/v1/auth/logout [post]
func LogoutHandler(w http.ResponseWriter, r *http.Request) {

	input, err := utils.BindAndValidate[models.LogoutRequest](r, http.MethodPost)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request", err.Error())
		return
	}

	userId, userpool, err := utils.ExtractUserIDFromIDToken(input.Idtoken)
	if err != nil {
		utils.WriteError(w, http.StatusForbidden, "Unable to Logout", err.Error())
		return
	}

	query := `UPDATE refresh_tokens SET revoked = true WHERE user_id = $1 AND revoked = false`
	_, err = db.GetDb().Exec(r.Context(), query, userId)
	if err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Complete Login", resp.Message)
		return
	}

	core.CaptureAudit(r.Context(), userpool, userId, userId, core.ActionUserLogout, (*core.AuditMetadata)(core.ExtractRequestMetadata(r)))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp := map[string]string{
		"message": "Logout Succesful!",
	}
	utils.WriteResponse(w, http.StatusOK, resp)
}

// PasswordResetRequestHandler godoc
// @Summary Request password reset OTP
// @Description Initiates a password reset by generating and sending an OTP to the registered email for the specified userpool.
// @Tags Authentication
// @Accept json
// @Produce json
// @Param input body models.PasswordResetRequest true "Password reset request containing email and userpool"
// @Success 200 {object} models.PasswordResetResponse "OTP sent successfully for password reset"
// @Failure 400 {object} models.ErrorResponse "Invalid request body, missing email, or validation error"
// @Failure 404 {object} models.ErrorResponse "User not found"
// @Failure 500 {object} models.ErrorResponse "Server or database error"
// @Router /api/v1/auth/password/request [post]
func PasswordResetRequestHandler(w http.ResponseWriter, r *http.Request) {

	input, err := utils.BindAndValidate[models.PasswordResetRequest](r, http.MethodPost)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request", err.Error())
		return
	}

	if !utils.IsValidEmail(input.Email) {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request", "Missing Email/userpool")
		return
	}

	var userId string
	query := `SELECT id FROM users WHERE email=$1 AND user_pool_id=$2`
	args := []any{input.Email, input.Userpool}
	if err := db.QueryRowAndScan(r.Context(), query, args, &userId); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Complete Login", resp.Message)
		return
	}

	otp, err := utils.GenerateOtp()
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to reset password", "Contact Admin")
		return
	}

	cache := &models.PasswordResetCache{
		UserID:   userId,
		Otp:      otp,
		Tries:    3,
		Userpool: input.Userpool,
	}
	cacheid := uuid.NewString()

	if err := db.RedisSet(r.Context(), cacheid, cache); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to reset password", err.Error())
		return
	}

	if err = utils.SendOtp(otp); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to reset password", err.Error())
		return
	}
	core.CaptureAudit(r.Context(), cache.Userpool, cache.UserID, cache.UserID, core.ActionPasswordResetReq, (*core.AuditMetadata)(core.ExtractRequestMetadata(r)))
	response := &models.PasswordResetResponse{
		Id:      cacheid,
		Message: "OTP SENT",
	}

	utils.WriteResponse(w, http.StatusOK, response)
}

// PasswordResetCompleteHandler godoc
// @Summary Complete password reset
// @Description Verifies the OTP and resets the user's password by updating the database record.
// @Tags Authentication
// @Accept json
// @Produce json
// @Param input body models.PasswordResetVerifyRequest true "Password reset verification request containing OTP and new password"
// @Success 200 {object} map[string]string "Password reset successful"
// @Failure 400 {object} models.ErrorResponse "Invalid request body, wrong OTP, or validation error"
// @Failure 404 {object} models.ErrorResponse "OTP session expired or user not found"
// @Failure 500 {object} models.ErrorResponse "Server or database error"
// @Router /api/v1/auth/password/reset [post]
func PasswordResetCompleteHandler(w http.ResponseWriter, r *http.Request) {

	input, err := utils.BindAndValidate[models.PasswordResetVerifyRequest](r, http.MethodPost)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request", err.Error())
		return
	}

	cache, err := db.RedisGet[models.PasswordResetCache](r.Context(), input.Id)

	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to verify OTP", err.Error())
		return
	}
	if cache == nil {
		utils.WriteError(w, http.StatusNotFound, "OTP session not found or expired", "")
		return
	}

	if input.Answer != cache.Otp {
		cache.Tries--
		if cache.Tries <= 0 {
			utils.WriteError(w, http.StatusInternalServerError, "Login Failed, To many wrong attempt", "Tries Left = 0")
			db.RedisDel(r.Context(), input.Id)
			return
		}
		message := fmt.Sprintf("Attempts left %d", cache.Tries)
		utils.WriteError(w, http.StatusBadRequest, "Please enter the right Otp", message)
		if err := db.RedisSet(r.Context(), input.Id, input); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, "Unable to Generate OTP", err.Error())
			return
		}
		return
	}

	hashedPassword, err := utils.CreateHash(input.Password)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Reset Password", err.Error())
		return
	}

	query := `UPDATE users SET password_hash=$1 WHERE id=$2`
	cmdTag, err := db.GetDb().Exec(r.Context(), query, hashedPassword, cache.UserID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Database error", err.Error())
		return
	}

	if cmdTag.RowsAffected() == 0 {
		utils.WriteError(w, http.StatusNotFound, "No user Id found", "Unable to reset password")
		return
	}

	if err = db.RedisDel(r.Context(), input.Id); err != nil {
		log.Printf("Redis Del Failed %s", err.Error())
	}

	core.CaptureAudit(r.Context(), cache.Userpool, cache.UserID, cache.UserID, core.ActionPasswordChanged, (*core.AuditMetadata)(core.ExtractRequestMetadata(r)))
	utils.WriteResponse(w, http.StatusOK, map[string]string{"message": "Password Reset"})
}

// ValidateTokenHandler godoc
// @Summary Validate access token
// @Description Introspects an access token to check if it is active. Returns {"active": true} with user info if valid, {"active": false} otherwise.
// @Tags Authentication
// @Accept x-www-form-urlencoded
// @Produce json
// @Param token formData string true "Access token to validate"
// @Success 200 {object} map[string]interface{} "Token introspection result containing active status, user id, userpool, scopes, and roles"
// @Router /api/v1/auth/introspect [post]
func ValidateToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteResponse(w, http.StatusOK, map[string]any{"active": false})
		return
	}

	accessToken := r.FormValue("token")
	if accessToken == "" {
		utils.WriteResponse(w, http.StatusOK, map[string]any{"active": false})
		return
	}

	userId, userpool, err := utils.ExtractInfo(accessToken)
	if err != nil {
		utils.WriteResponse(w, http.StatusOK, map[string]any{"active": false})
		return
	}

	permissions, roles, err := db.GetUserRolesAndPermissions(r.Context(), userId)
	if err != nil {
		utils.WriteResponse(w, http.StatusOK, map[string]any{"active": false})
		return
	}

	if err := utils.ValidateAccessToken(accessToken, permissions, roles); err != nil {
		utils.WriteResponse(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	response := map[string]any{
		"active":   true,
		"sub":      userId,
		"userpool": userpool,
		"scopes":   permissions,
		"roles":    roles,
	}
	utils.WriteResponse(w, http.StatusOK, response)
}
