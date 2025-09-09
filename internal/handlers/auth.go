package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
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
// @Param        input  body      models.SignupPhoneRequest   true  "Signup phone request data"
// @Success      200    {object}  models.SignupPhoneResponse  "OTP sent successfully"
// @Failure      400    {object}  models.ErrorResponse        "Missing/Invalid essential inputs"
// @Failure      409    {object}  models.ErrorResponse        "Phone number already registered"
// @Failure      500    {object}  models.ErrorResponse        "Database or server error"
// @Router       /api/v1/auth/signup/phone/request [post]

func SignupPhoneOtpRequestHandler(w http.ResponseWriter, r *http.Request) {
	var input models.SignupPhoneRequest
	var user models.UserSignupData

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		utils.WriteError(w, http.StatusMethodNotAllowed, "Invalid Request Method", "")
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request Body", err.Error())
		return
	}

	if err := utils.ValidateInput(input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Validation Error", err.Error())
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// SignupEmailOtpRequestHandler godoc
// @Summary      Request email signup OTP
// @Description  Validates signup session ID, email, and password, generates an OTP, stores it in Redis, and sends it to the email.
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Param        input  body      models.SignupEmailRequest   true  "Signup email request data"
// @Success      200    {object}  models.SignupEmailResponse  "OTP sent successfully"
// @Failure      400    {object}  models.ErrorResponse        "Invalid request body or signup ID"
// @Failure      500    {object}  models.ErrorResponse        "Database or server error"
// @Router       /api/v1/auth/signup/email/request [post]

func SignupEmailOtpRequestHandler(w http.ResponseWriter, r *http.Request) {
	var input models.SignupEmailRequest
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

	if err := utils.ValidateInput(input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Validation Error", err.Error())
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// SignupPhoneOtpVerifyHandler godoc
// @Summary      Verify phone signup OTP
// @Description  Verifies the phone OTP and marks the phone as verified in the signup session.
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Param        input  body      models.UserSignupVerification  true  "Phone OTP verification request"
// @Success      200    {object}  models.UserSignupResponse      "Phone verified successfully"
// @Failure      400    {object}  models.ErrorResponse           "Invalid signup ID or wrong OTP"
// @Failure      500    {object}  models.ErrorResponse           "Server error"
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

	if err := utils.ValidateInput(input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Validation Error", err.Error())
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
		Message: "OTP sent successfully",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// SignupVerifyAndCompleteHandler godoc
// @Summary      Verify email OTP and complete signup
// @Description  Verifies the OTP sent to the email, ensures phone is verified, creates the user account in DB, generates tokens, and completes signup.
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Param        input  body      models.UserSignupVerification   true  "Email OTP verification request"
// @Success      200    {object}  models.SignupCompleteResponse   "Signup completed successfully with tokens"
// @Failure      400    {object}  models.ErrorResponse            "Invalid signup ID or wrong OTP"
// @Failure      406    {object}  models.ErrorResponse            "Phone not verified"
// @Failure      500    {object}  models.ErrorResponse            "Server or database error"
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

	if err := utils.ValidateInput(input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Validation Error", err.Error())
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

	tokens, err := utils.GenerateTokens(userId, user.Email, user.Phone, permissions, []string{"user"})
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

	response := &models.SignupCompleteResponse{
		Id:           input.ID,
		UserId:       userId,
		Message:      "Account Creation Succesful",
		IdToken:      tokens.IDToken,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// PasswordLoginHandler godoc
// @Summary      Login with email and password
// @Description  Authenticates a user using email, password, and userpool. Returns ID, access, and refresh tokens on success.
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Param        input  body      models.PasswordLoginRequest  true  "Password login request"
// @Success      200    {object}  models.LoginResponse         "Login successful with tokens"
// @Failure      400    {object}  models.ErrorResponse         "Invalid request body"
// @Failure      401    {object}  models.ErrorResponse         "Incorrect password"
// @Failure      404    {object}  models.ErrorResponse         "User not found"
// @Failure      500    {object}  models.ErrorResponse         "Server or database error"
// @Router       /api/v1/auth/login/password [post]

func PasswordLoginHandler(w http.ResponseWriter, r *http.Request) {
	var input models.PasswordLoginRequest

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		utils.WriteError(w, http.StatusMethodNotAllowed, "Invalid Status Used", "")
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request Body!", err.Error())
		return
	}

	if err := utils.ValidateInput(input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Validation Error", err.Error())
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

	tokens, err := utils.GenerateTokens(id, input.Email, phone, permissions, roles)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Login", err.Error())
		return
	}

	response := &models.LoginResponse{
		Message:      "Login Successful",
		IdToken:      tokens.IDToken,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// LoginOtpRequestHandler godoc
// @Summary      Request OTP for login
// @Description  Starts OTP-based login by sending OTP to email or phone (based on method).
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Param        input  body      models.OtpLoginRequest   true  "Login OTP request"
// @Success      200    {object}  models.OtpLoginResponse  "OTP sent successfully"
// @Failure      400    {object}  models.ErrorResponse     "Invalid request body or method"
// @Failure      404    {object}  models.ErrorResponse     "User not found"
// @Failure      500    {object}  models.ErrorResponse     "Server or database error"
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

	if err := utils.ValidateInput(input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Validation Error", err.Error())
		return
	}

	var query, userid string

	switch input.Method {
	case "phone":
		query = `SELECT id FROM users WHERE phone=$1 AND user_pool_id=$2`
	case "email":
		query = `SELECT id FROM users WHERE email=$1 AND user_pool_id=$2`
	default:
		utils.WriteError(w, http.StatusBadRequest, "Invalid Method", "use phone/email")
		return
	}

	args := []any{input.Credential, input.Userpool}
	if err := db.QueryRowAndScan(r.Context(), query, args, &userid); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Complete Login", resp.Message)
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
		UserId: userid,
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// LoginOtpVerifyHandler godoc
// @Summary      Verify OTP for login
// @Description  Verifies OTP and issues ID, access, and refresh tokens for user login.
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Param        input  body      models.OtpLoginVerifyRequest  true  "Login OTP verification request"
// @Success      200    {object}  models.LoginResponse          "Login successful with tokens"
// @Failure      400    {object}  models.ErrorResponse          "Invalid input or wrong OTP"
// @Failure      404    {object}  models.ErrorResponse          "OTP session expired or user not found"
// @Failure      500    {object}  models.ErrorResponse          "Server or database error"
// @Router       /api/v1/auth/login/otp/verify [post]

func LoginOtpVerifyHandler(w http.ResponseWriter, r *http.Request) {
	var input models.OtpLoginVerifyRequest

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		utils.WriteError(w, http.StatusMethodNotAllowed, "Invalid Method", "Use Post Method")
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request body", "Invalid Request Body")
		return
	}

	if err := utils.ValidateInput(input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Validation Error", err.Error())
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

	var email, phone string
	query := `SELECT email, phone FROM users WHERE id=$1`
	args := []any{cache.UserId}
	if err := db.QueryRowAndScan(r.Context(), query, args, &email, &phone); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Complete Login", resp.Message)
		return
	}

	permissions, roles, err := db.GetUserRolesAndPermissions(r.Context(), cache.UserId)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Login", err.Error())
		return
	}

	tokens, err := utils.GenerateTokens(cache.UserId, email, phone, permissions, roles)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Login Failed", err.Error())
		return
	}

	query = `DELETE FROM refresh_tokens WHERE user_id=$1`
	_, err = db.GetDb().Exec(r.Context(), query, cache.UserId)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Failed to delete old tokens", err.Error())
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
	args = []any{cache.UserId, hashedToken, time.Now().Add(365 * time.Minute)}
	if err := db.QueryRowAndScan(r.Context(), query, args, &tokenID); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, http.StatusInternalServerError, "Unable to Complete Login", resp.Message)
		return
	}

	if err = db.RedisDel(r.Context(), input.Id); err != nil {
		log.Printf("Unable to delete Key/Value in redis %s", err.Error())
	}
	response := &models.LoginResponse{
		Message:      "Login Successful",
		IdToken:      tokens.IDToken,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
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
	var token models.RefreshSessionRequest

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		utils.WriteError(w, http.StatusMethodNotAllowed, "Invalid Method", "Use Post Method")
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&token); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request body", "Invalid Request Body")
		return
	}

	if err := utils.ValidateInput(token); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Validation Error", err.Error())
		return
	}

	userId, err := utils.ExtractUserIDFromIDToken(token.Idtoken)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Login Failed", "")
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
		utils.WriteError(w, http.StatusUnauthorized, "Incorrect Password", "Plase enter the correct password")
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

	newTokens, err := utils.RefreshTokens(userId, email, phone, permissions, roles)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Login Failed", err.Error())
		return
	}

	response := &models.RefreshSessionResponse{
		Message:     "Session Refresh successfully",
		IdToken:     newTokens.IDToken,
		AccessToken: newTokens.AccessToken,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// LogoutHandler godoc
// @Summary      Logout user
// @Description  Logs out the user by revoking all refresh tokens for the given user.
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Param        input  body      models.LogoutRequest  true  "Logout request"
// @Success      200    {object}  map[string]string     "Logout successful"
// @Failure      400    {object}  models.ErrorResponse  "Invalid request body"
// @Failure      403    {object}  models.ErrorResponse  "Unable to extract user ID"
// @Failure      500    {object}  models.ErrorResponse  "Database error"
// @Router       /api/v1/auth/logout [post]

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	var input models.LogoutRequest

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		utils.WriteError(w, http.StatusMethodNotAllowed, "Invalid Method", "Use POST")
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request body", "Invalid Request Body")
		return
	}

	if err := utils.ValidateInput(input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Validation Error", err.Error())
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
// @Param        input  body      models.PasswordResetRequest   true  "Password reset request"
// @Success      200    {object}  models.PasswordResetResponse  "OTP sent for password reset"
// @Failure      400    {object}  models.ErrorResponse          "Invalid request body"
// @Failure      404    {object}  models.ErrorResponse          "User not found"
// @Failure      500    {object}  models.ErrorResponse          "Server or database error"
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

	if err := utils.ValidateInput(input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Validation Error", err.Error())
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
		Otp:   otp,
		Tries: 3,
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

	response := &models.PasswordResetResponse{
		Id:      cacheid,
		Message: "OTP SENT",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// PasswordResetCompleteHandler godoc
// @Summary      Complete password reset
// @Description  Verifies OTP and resets user password by updating DB record.
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Param        input  body      models.PasswordResetVerifyRequest  true  "Password reset verification"
// @Success      200    {object}  map[string]string                  "Password reset successful"
// @Failure      400    {object}  models.ErrorResponse               "Invalid request body or wrong OTP"
// @Failure      404    {object}  models.ErrorResponse               "OTP session expired or user not found"
// @Failure      500    {object}  models.ErrorResponse               "Server or database error"
// @Router       /api/v1/auth/password/reset [post]

func PasswordResetCompleteHandler(w http.ResponseWriter, r *http.Request) {
	var input models.PasswordResetVerifyRequest

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		utils.WriteError(w, http.StatusMethodNotAllowed, "Invalid Method", "Use POST")
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Invalid Request body", "Invalid Request Body")
		return
	}

	if err := utils.ValidateInput(input); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "Validation Error", err.Error())
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
