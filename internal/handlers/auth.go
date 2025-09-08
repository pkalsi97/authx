package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/pkalsi97/authx/internal/db"
	"github.com/pkalsi97/authx/internal/models"
	"github.com/pkalsi97/authx/internal/utils"
)

// SignupPhoneOtpRequestHandler godoc
// @Summary      Request phone signup OTP
// @Description  Validates phone and userpool, generates an OTP, stores it in Redis, and sends it to the phone.
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Param        input  body      models.UserSignupData  true  "Signup phone request data"
// @Success      200    {object}  map[string]string       "OTP sent successfully"
// @Failure      400    {object}  models.ErrorResponse    "Missing/Invalid essential inputs"
// @Failure      409    {object}  models.ErrorResponse    "Phone number already registered"
// @Failure      500    {object}  models.ErrorResponse    "Database or server error"
// @Router       /api/v1/auth/signup/phone/request [post]

func SignupPhoneOtpRequestHandler(w http.ResponseWriter, r *http.Request) {
	var input models.UserSignupData

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		utils.WriteError(w, http.StatusMethodNotAllowed, "Invalid Request Method", "")
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request Body", err.Error())
		return
	}
	cleanPhone, valid := utils.IsValidPhone(input.Phone)

	if input.Userpool == "" || !valid {
		utils.WriteError(w, http.StatusBadRequest, "Missing/Invalid Essential Inputs", "")
		return
	}

	input.Phone = cleanPhone

	var userPoolExists bool
	queryUserpool := `SELECT EXISTS(SELECT 1 FROM user_pools WHERE id=$1)`
	err := db.GetDb().QueryRow(r.Context(), queryUserpool, input.Userpool).Scan(&userPoolExists)
	if !userPoolExists {
		utils.WriteError(w, http.StatusBadRequest, "Unable to proceed with the Signup", "Userpool does not exist")
		return
	}
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Database error", err.Error())
		return
	}

	var phoneExists bool
	queryPhone := `SELECT EXISTS(SELECT 1 FROM users WHERE phone=$1)`
	err = db.GetDb().QueryRow(r.Context(), queryPhone, input.Phone).Scan(&phoneExists)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Database error", err.Error())
		return
	}
	if phoneExists {
		utils.WriteError(w, http.StatusConflict, "Phone number already registered", "")
		return
	}

	otp, err := utils.GenerateOtp()
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Generate OTP", err.Error())
		return
	}

	input.PhoneOtp = otp
	input.PhoneTries = 3
	input.EmailTries = 3
	input.ID = uuid.NewString()

	if err := db.RedisSet(r.Context(), input.ID, &input); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Generate OTP", err.Error())
		return
	}

	if err := utils.SendOtp(otp); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Send OTP", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	resp := map[string]string{
		"id":      input.ID,
		"message": "OTP sent successfully",
	}
	json.NewEncoder(w).Encode(resp)
}

// SignupEmailOtpRequestHandler godoc
// @Summary      Request email signup OTP
// @Description  Validates signup session ID, email, and password, generates an OTP, stores it in Redis, and sends it to the email.
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Param        input  body      models.UserSignupData  true  "Signup email request data"
// @Success      200    {object}  map[string]string       "OTP sent successfully"
// @Failure      400    {object}  models.ErrorResponse    "Invalid request body or signup ID"
// @Failure      500    {object}  models.ErrorResponse    "Database or server error"
// @Router       /api/v1/auth/signup/email/request [post]

func SignupEmailOtpRequestHandler(w http.ResponseWriter, r *http.Request) {
	var input models.UserSignupData
	var user *models.UserSignupData

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		utils.WriteError(w, http.StatusMethodNotAllowed, "Invalid Request Method", "")
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request Body", err.Error())
		return
	}

	if input.ID == "" || !utils.IsValidEmail(input.Email) || input.Password == "" {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request Body", "")
		return
	}

	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)`
	err := db.GetDb().QueryRow(r.Context(), query, input.Email).Scan(&exists)
	if !exists {
		utils.WriteError(w, http.StatusBadRequest, "Unable to proceed with the Signup", "Userpool does not exist")
		return
	}
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Database error", err.Error())
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

	user.Email = input.Email
	user.EmailOtp = otp
	user.Password = hashedPassword

	if err := db.RedisSet(r.Context(), input.ID, user); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Generate OTP", err.Error())
		return
	}

	if err := utils.SendOtp(otp); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Send OTP", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp := map[string]string{
		"id":      input.ID,
		"message": "OTP sent successfully",
	}
	json.NewEncoder(w).Encode(resp)
}

// SignupPhoneOtpVerifyHandler godoc
// @Summary      Verify phone OTP
// @Description  Verifies the OTP sent to the phone during signup. Marks phone as verified if OTP is correct.
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Param        input  body      models.UserSignupVerification  true  "Phone OTP verification request"
// @Success      200    {object}  map[string]string              "OTP Verified successfully"
// @Failure      400    {object}  models.ErrorResponse           "Invalid signup ID or wrong OTP"
// @Failure      406    {object}  models.ErrorResponse           "Retry attempts exhausted"
// @Failure      500    {object}  models.ErrorResponse           "Server or database error"
// @Router       /api/v1/auth/signup/phone/verify [post]

func SignupPhoneOtpVerifyHandler(w http.ResponseWriter, r *http.Request) {
	var input models.UserSignupVerification
	var user *models.UserSignupData

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		utils.WriteError(w, http.StatusMethodNotAllowed, "Invalid Request Method", "")
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request Body", err.Error())
		return
	}

	if input.ID == "" || input.Answer == "" {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request Body", "")
		return
	}

	user, err := db.RedisGet[models.UserSignupData](r.Context(), input.ID)
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
	user.PhoneTries--

	if answer != otp {
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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp := map[string]string{
		"id":      input.ID,
		"message": "OTP Verified",
	}
	json.NewEncoder(w).Encode(resp)
}

// SignupVerifyAndCompleteHandler godoc
// @Summary      Verify email OTP and complete signup
// @Description  Verifies the OTP sent to the email, ensures phone is verified, creates the user account in DB, generates tokens, and completes signup.
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Param        input  body      models.UserSignupVerification  true  "Email OTP verification request"
// @Success      200    {object}  map[string]string              "Signup completed successfully with tokens"
// @Failure      400    {object}  models.ErrorResponse           "Invalid signup ID or wrong OTP"
// @Failure      406    {object}  models.ErrorResponse           "Phone not verified"
// @Failure      500    {object}  models.ErrorResponse           "Server or database error"
// @Router       /api/v1/auth/signup/complete [post]

func SignupVerifyAndCompleteHandler(w http.ResponseWriter, r *http.Request) {
	var input models.UserSignupVerification
	var user *models.UserSignupData

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		utils.WriteError(w, http.StatusMethodNotAllowed, "Invalid Request Method", "")
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request Body", err.Error())
		return
	}

	if input.ID == "" || input.Answer == "" {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request Body", "")
		return
	}
	user, err := db.RedisGet[models.UserSignupData](r.Context(), input.ID)
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
	user.EmailTries--

	if answer != otp {
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

	dbClient := db.GetDb()
	userpool := user.Userpool
	var schema map[string]interface{}

	row := dbClient.QueryRow(
		r.Context(),
		`SELECT schema FROM user_pools WHERE id=$1 `,
		userpool,
	)

	var schemaBytes []byte
	if err := row.Scan(&schemaBytes); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Complete Signup", err.Error())
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

	row = db.GetDb().QueryRow(
		r.Context(),
		`INSERT INTO users(user_pool_id, email, email_verified, phone, phone_verified, password_hash, metadata)
    VALUES($1,$2,$3,$4,$5,$6,$7)
    RETURNING id`,
		userpool, user.Email, user.EmailVerified, user.Phone, user.PhoneVerified, user.Password, metadataBytes,
	)

	var userId string
	if err := row.Scan(&userId); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Complete Signup", err.Error())
		return
	}

	tokens, err := utils.GenerateTokens(userId, user.Email, user.Phone)
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

	row = dbClient.QueryRow(
		r.Context(),
		`INSERT INTO refresh_tokens (user_id, token_hash,expires_at)
		VALUES($1,$2,$3)
		RETURNING id`,
		userId, hashedToken, time.Now().Add(365*time.Minute),
	)

	var tokenID string
	err = row.Scan(&tokenID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Signup complete but unable to login", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp := map[string]string{
		"id":            input.ID,
		"user_id":       userId,
		"message":       "Account Creation Succesful",
		"id_token":      tokens.IDToken,
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
	}
	json.NewEncoder(w).Encode(resp)
}

// PasswordLoginHandler godoc
// @Summary      Login with email and password
// @Description  Authenticates a user using email, password, and userpool. Returns ID, access, and refresh tokens on success.
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Param        input  body      models.PasswordLogin   true  "Password login request"
// @Success      200    {object}  map[string]string      "Login successful with tokens"
// @Failure      400    {object}  models.ErrorResponse   "Invalid request body"
// @Failure      401    {object}  models.ErrorResponse   "Incorrect password"
// @Failure      404    {object}  models.ErrorResponse   "User not found"
// @Failure      500    {object}  models.ErrorResponse   "Server or database error"
// @Router       /api/v1/auth/login/password [post]

func PasswordLoginHandler(w http.ResponseWriter, r *http.Request) {
	var input models.PasswordLogin

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		utils.WriteError(w, http.StatusMethodNotAllowed, "Invalid Status Used", "")
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request Body!", err.Error())
		return
	}

	var id, phone, password_hash string

	query := `SELECT id, phone, password_hash FROM users WHERE email=$1 AND user_pool_id=$2`
	row := db.GetDb().QueryRow(r.Context(), query, input.Email, input.Userpool)

	err := row.Scan(&id, &phone, &password_hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			utils.WriteError(w, http.StatusNotFound, "User not found", "")
			return
		}
		utils.WriteError(w, http.StatusInternalServerError, "Database error", err.Error())
		return
	}

	match := utils.CompareHash(password_hash, input.Password)
	if !match {
		utils.WriteError(w, http.StatusUnauthorized, "Incorrect Password", "Plase enter the correct password")
		return
	}

	tokens, err := utils.GenerateTokens(id, input.Email, phone)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Login", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp := map[string]string{
		"message":       "Login Succesful!",
		"id_token":      tokens.IDToken,
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
	}
	json.NewEncoder(w).Encode(resp)

}

// LoginOtpRequestHandler godoc
// @Summary      Request OTP for login
// @Description  Starts OTP-based login by sending OTP to email or phone (based on method).
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Param        input  body      models.OtpLoginRequest  true  "Login OTP request"
// @Success      200    {object}  map[string]string       "OTP sent successfully"
// @Failure      400    {object}  models.ErrorResponse    "Invalid request body or method"
// @Failure      404    {object}  models.ErrorResponse    "User not found"
// @Failure      500    {object}  models.ErrorResponse    "Server or database error"
// @Router       /api/v1/auth/login/otp/request [post]

func LoginOtpRequestHandler(w http.ResponseWriter, r *http.Request) {
	var input models.OtpLoginRequest

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		utils.WriteError(w, http.StatusMethodNotAllowed, "Incorrect Method", "Use POST")
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request Body", err.Error())
		return
	}
	var query, id string

	switch input.Method {
	case "phone":
		query = `SELECT id FROM users WHERE phone=$1 AND user_pool_id=$2`
	case "email":
		query = `SELECT id FROM users WHERE email=$1 AND user_pool_id=$2`
	default:
		utils.WriteError(w, http.StatusBadRequest, "Invalid Method", "use phone/email")
		return
	}

	row := db.GetDb().QueryRow(r.Context(), query, input.Credential, input.Userpool)

	err := row.Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			utils.WriteError(w, http.StatusNotFound, "User not found", "")
			return
		}
		utils.WriteError(w, http.StatusInternalServerError, "Database error", err.Error())
		return
	}

	otp, err := utils.GenerateOtp()
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Login Request Failed", err.Error())
		return
	}

	data := &models.OtpCacheData{
		Method: input.Method,
		Otp:    otp,
		Tries:  3,
	}

	if err := db.RedisSet(r.Context(), id, data); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Login Request Failed", err.Error())
		return
	}

	if err := utils.SendOtp(otp); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Send OTP", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp := map[string]string{
		"id":      id,
		"message": "OTP sent successfully",
	}
	json.NewEncoder(w).Encode(resp)

}

// LoginOtpVerifyHandler godoc
// @Summary      Verify OTP for login
// @Description  Verifies OTP and issues ID, access, and refresh tokens for user login.
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Param        input  body      models.OtpLoginVerify   true  "Login OTP verification request"
// @Success      200    {object}  map[string]string       "Login successful with tokens"
// @Failure      400    {object}  models.ErrorResponse    "Invalid input or wrong OTP"
// @Failure      404    {object}  models.ErrorResponse    "OTP session expired or user not found"
// @Failure      500    {object}  models.ErrorResponse    "Server or database error"
// @Router       /api/v1/auth/login/otp/verify [post]

func LoginOtpVerifyHandler(w http.ResponseWriter, r *http.Request) {
	var input models.OtpLoginVerify

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		utils.WriteError(w, http.StatusMethodNotAllowed, "Invalid Method", "Use Post Method")
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request body", "Invalid Request Body")
		return
	}

	if input.Id == "" || input.Answer == "" {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request Body", "id and answer are required")
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

	cache.Tries--
	if input.Answer != cache.Otp {
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

	var email, phone string
	query := `SELECT email, phone FROM users WHERE id=$1`
	if err := db.GetDb().QueryRow(r.Context(), query, input.Id).Scan(&email, &phone); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Database error", err.Error())
		return
	}

	tokens, err := utils.GenerateTokens(input.Id, email, phone)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Login Failed", err.Error())
		return
	}

	query = `DELETE FROM refresh_tokens WHERE user_id=$1`
	_, err = db.GetDb().Exec(r.Context(), query, input.Id)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Failed to delete old tokens", err.Error())
		return
	}

	hashedToken, err := utils.CreateHash(tokens.RefreshToken)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Login Failed", err.Error())
		return
	}

	row := db.GetDb().QueryRow(
		r.Context(),
		`INSERT INTO refresh_tokens (user_id, token_hash,expires_at)
		VALUES($1,$2,$3)
		RETURNING id`,
		input.Id, hashedToken, time.Now().Add(365*time.Minute),
	)

	var tokenID string
	err = row.Scan(&tokenID)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Login Failed", err.Error())
		return
	}

	if err = db.RedisDel(r.Context(), input.Id); err != nil {
		log.Printf("Unable to delete Key/Value in redis %s", err.Error())
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp := map[string]string{
		"message":       "Login successfully",
		"id_token":      tokens.IDToken,
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
	}
	json.NewEncoder(w).Encode(resp)
}

// SessionRefreshHandler godoc
// @Summary      Refresh session tokens
// @Description  Uses refresh token and ID token to generate new ID and access tokens.
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Param        input  body      models.RefreshSession   true  "Session refresh request"
// @Success      200    {object}  map[string]string       "New tokens returned"
// @Failure      400    {object}  models.ErrorResponse    "Invalid request body"
// @Failure      401    {object}  models.ErrorResponse    "Invalid or mismatched refresh token"
// @Failure      404    {object}  models.ErrorResponse    "User not found"
// @Failure      500    {object}  models.ErrorResponse    "Server or database error"
// @Router       /api/v1/auth/session/refresh [post]

func SessionRefreshHandler(w http.ResponseWriter, r *http.Request) {
	var token models.RefreshSession

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		utils.WriteError(w, http.StatusMethodNotAllowed, "Invalid Method", "Use Post Method")
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&token); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request body", "Invalid Request Body")
		return
	}

	if token.Refreshtoken == "" || token.Idtoken == "" {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request Body", "id and answer are required")
		return
	}

	userId, err := utils.ExtractUserIDFromIDToken(token.Idtoken)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Login Failed", "")
		return
	}

	var tokenHash string
	query := `SELECT token_hash FROM refresh_tokens WHERE user_id=$1 AND revoked=false`
	err = db.GetDb().QueryRow(r.Context(), query, userId).Scan(&tokenHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			utils.WriteError(w, http.StatusNotFound, "User not found", "")
			return
		}
		utils.WriteError(w, http.StatusInternalServerError, "Database error", err.Error())
		return
	}

	if !utils.CompareHash(tokenHash, token.Refreshtoken) {
		utils.WriteError(w, http.StatusUnauthorized, "Incorrect Password", "Plase enter the correct password")
		return
	}

	var email, phone string
	query = `SELECT email, phone FROM users WHERE id=$1`
	err = db.GetDb().QueryRow(r.Context(), query, userId).Scan(&email, &phone)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			utils.WriteError(w, http.StatusNotFound, "Email/ Phone", "")
			return
		}
		utils.WriteError(w, http.StatusInternalServerError, "Database error", err.Error())
		return
	}

	newTokens, err := utils.RefreshTokens(userId, email, phone)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Login Failed", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp := map[string]string{
		"message":      "Session Refresh successfully",
		"id_token":     newTokens.IDToken,
		"access_token": newTokens.AccessToken,
	}
	json.NewEncoder(w).Encode(resp)

}

// LogoutHandler godoc
// @Summary      Logout user
// @Description  Logs out the user by revoking all refresh tokens for the given user.
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Param        input  body      models.RefreshSession   true  "Logout request"
// @Success      200    {object}  map[string]string       "Logout successful"
// @Failure      400    {object}  models.ErrorResponse    "Invalid request body"
// @Failure      403    {object}  models.ErrorResponse    "Unable to extract user ID"
// @Failure      500    {object}  models.ErrorResponse    "Database error"
// @Router       /api/v1/auth/logout [post]

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	var input models.RefreshSession

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		utils.WriteError(w, http.StatusMethodNotAllowed, "Invalid Method", "Use POST")
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request body", "Invalid Request Body")
		return
	}

	if input.Idtoken == "" || input.Refreshtoken == "" {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request", "Missing Id/Refresh Token")
		return
	}

	userId, err := utils.ExtractUserIDFromIDToken(input.Idtoken)
	if err != nil {
		utils.WriteError(w, http.StatusForbidden, "Unable to Logout", err.Error())
		return
	}

	query := `DELETE FROM refresh_tokens WHERE user_id=$1`
	_, err = db.GetDb().Exec(r.Context(), query, userId)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Failed to delete old tokens", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp := map[string]string{
		"message": "Logout Succesful!",
	}
	json.NewEncoder(w).Encode(resp)
}

// PasswordResetRequestHandler godoc
// @Summary      Request password reset
// @Description  Starts password reset by sending OTP to registered email for the given userpool.
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Param        input  body      models.PasswordResetRequest  true  "Password reset request"
// @Success      200    {object}  map[string]string            "OTP sent for password reset"
// @Failure      400    {object}  models.ErrorResponse         "Invalid request body"
// @Failure      404    {object}  models.ErrorResponse         "User not found"
// @Failure      500    {object}  models.ErrorResponse         "Server or database error"
// @Router       /api/v1/auth/password/request [post]

func PasswordResetRequestHandler(w http.ResponseWriter, r *http.Request) {
	var input models.PasswordResetRequest

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		utils.WriteError(w, http.StatusMethodNotAllowed, "Invalid Method", "Use POST")
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request body", "Invalid Request Body")
		return
	}

	if !utils.IsValidEmail(input.Email) || input.Userpool == "" {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request", "Missing Email/userpool")
		return
	}

	var userId string
	query := `SELECT id FROM users WHERE email=$1 AND user_pool_id=$2`
	err := db.GetDb().QueryRow(r.Context(), query, input.Email, input.Userpool).Scan(&userId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			utils.WriteError(w, http.StatusNotFound, "No user Id found", "Unable to reset password")
			return
		}
		utils.WriteError(w, http.StatusInternalServerError, "Database error", err.Error())
		return
	}

	otp, err := utils.GenerateOtp()
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to reset password", "Contact Admin")
		return
	}

	cache := &models.PasswordResetCache{
		Id:    userId,
		Otp:   otp,
		Tries: 3,
	}

	if err := db.RedisSet(r.Context(), userId+"reset", cache); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to reset password", err.Error())
		return
	}

	if err = utils.SendOtp(otp); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to reset password", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp := map[string]string{
		"message": "OTP SENT",
		"id":      userId,
	}
	json.NewEncoder(w).Encode(resp)

}

// PasswordResetCompleteHandler godoc
// @Summary      Complete password reset
// @Description  Verifies OTP and resets user password by updating DB record.
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Param        input  body      models.PasswordResetVerify   true  "Password reset verification"
// @Success      200    {object}  map[string]string            "Password reset successful"
// @Failure      400    {object}  models.ErrorResponse         "Invalid request body or wrong OTP"
// @Failure      404    {object}  models.ErrorResponse         "OTP session expired or user not found"
// @Failure      500    {object}  models.ErrorResponse         "Server or database error"
// @Router       /api/v1/auth/password/reset [post]

func PasswordResetCompleteHandler(w http.ResponseWriter, r *http.Request) {
	var input models.PasswordResetVerify

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		utils.WriteError(w, http.StatusMethodNotAllowed, "Invalid Method", "Use POST")
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request body", "Invalid Request Body")
		return
	}

	if input.Answer == "" || input.Id == "" || input.Password == "" {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request", "Missing Email/userpool")
		return
	}

	cache, err := db.RedisGet[models.PasswordResetCache](r.Context(), input.Id+"reset")

	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to verify OTP", err.Error())
		return
	}
	if cache == nil {
		utils.WriteError(w, http.StatusNotFound, "OTP session not found or expired", "")
		return
	}

	cache.Tries--
	if input.Answer != cache.Otp {
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

	cmdTag, err := db.GetDb().Exec(r.Context(), query, hashedPassword, input.Id)
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp := map[string]string{
		"message": "Password Reset",
	}
	json.NewEncoder(w).Encode(resp)
}
