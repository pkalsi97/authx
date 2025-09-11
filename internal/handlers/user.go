package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/google/uuid"
	"github.com/pkalsi97/authx/internal/core"
	"github.com/pkalsi97/authx/internal/db"
	"github.com/pkalsi97/authx/internal/models"
	"github.com/pkalsi97/authx/internal/utils"
)

// UserPasswordResetHandler godoc
// @Summary      Reset user password
// @Description  Allows a logged-in user to reset their password by verifying the old password and setting a new one.
// @Tags         User-management
// @Accept       json
// @Produce      json
// @Param        input  body      models.UserPasswordResetRequest  true  "Password reset request"
// @Success      200    {object}  map[string]string               "Password Reset Successful"
// @Failure      400    {object}  models.ErrorResponse            "Invalid request body or validation error"
// @Failure      401    {object}  models.ErrorResponse            "Unauthorized or incorrect current password"
// @Failure      404    {object}  models.ErrorResponse            "User not found"
// @Failure      500    {object}  models.ErrorResponse            "Server or database error"
// @Router       /api/v1/users/password/reset [post]
func UserPasswordResetHandler(w http.ResponseWriter, r *http.Request) {
	var input models.UserPasswordResetRequest

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		utils.WriteError(w, http.StatusMethodNotAllowed, "Invalid Method", "Use POST")
		return
	}

	idToken, accessToken := r.Header.Get("ID-TOKEN"), r.Header.Get("ACCESS-TOKEN")

	if idToken == "" || accessToken == "" {
		utils.WriteError(w, http.StatusUnauthorized, "Missing Headers", "ID-TOKEN / ACCESS-TOKEN is Missing!")
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

	userId, userpool, err := utils.ExtractUserIDFromIDToken(idToken)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Password Reset Request Failed", err.Error())
		return
	}

	permissions, roles, err := db.GetUserRolesAndPermissions(r.Context(), userId)
	if err != nil {
		utils.WriteError(w, http.StatusUnauthorized, "Database error", "code x")
		return
	}

	if err := utils.ValidateAccessToken(accessToken, permissions, roles); err != nil {
		utils.WriteError(w, http.StatusUnauthorized, "Password Reset Request Failed", err.Error())
		return
	}

	var passwordHash string
	query := `SELECT password_hash FROM users WHERE id=$1`
	args := []any{userId}
	if err := db.QueryRowAndScan(r.Context(), query, args, &passwordHash); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, resp.Status, "Database Error", resp.Message)
		return
	}

	if !utils.CompareHash(passwordHash, input.OldPassword) {
		utils.WriteError(w, http.StatusUnauthorized, "Unauthorised", "Incorrect Current Password")
		return
	}

	newPasswordHash, err := utils.CreateHash(input.NewPassword)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Password Reset Failed", err.Error())
		return
	}

	query = `UPDATE users SET password_hash=$1 WHERE id=$2 Returning id`
	args = []any{newPasswordHash, userId}
	if err := db.QueryRowAndScan(r.Context(), query, args, &userId); err != nil {
		resp := db.MapDbError(err)
		utils.WriteError(w, resp.Status, "Database Error", resp.Message)
		return
	}
	core.CaptureAudit(r.Context(), userpool, userId, userId, core.ActionPasswordChanged, (*core.AuditMetadata)(core.ExtractRequestMetadata(r)))
	response := map[string]string{
		"message": "Password Reset Successful",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// CredentialRequestHandler godoc
// @Summary      Request OTP for credential reset
// @Description  Generates and sends an OTP for resetting a user credential (email or phone).
// @Tags         User-management
// @Accept       json
// @Produce      json
// @Param        input  body      models.UserCredentialRequest  true  "Credential reset request containing credential type (email/phone) and value"
// @Success      200    {object}  models.UserCredentialResponse "OTP sent successfully with cache ID"
// @Failure      400    {object}  models.ErrorResponse         "Invalid request body or validation error"
// @Failure      401    {object}  models.ErrorResponse         "Unauthorized (missing/invalid ID-TOKEN or ACCESS-TOKEN)"
// @Failure      500    {object}  models.ErrorResponse         "Server or database error"
// @Router       /api/v1/users/credential/request [post]
func CredentialRequestHandler(w http.ResponseWriter, r *http.Request) {
	var input models.UserCredentialRequest
	var response models.UserCredentialResponse

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		utils.WriteError(w, http.StatusMethodNotAllowed, "Invalid Method", "Use POST")
		return
	}

	idToken, accessToken := r.Header.Get("ID-TOKEN"), r.Header.Get("ACCESS-TOKEN")

	if idToken == "" || accessToken == "" {
		utils.WriteError(w, http.StatusUnauthorized, "Missing Headers", "ID-TOKEN / ACCESS-TOKEN is Missing!")
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

	userId, userpool, err := utils.ExtractUserIDFromIDToken(idToken)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Password Reset Request Failed", err.Error())
		return
	}

	permissions, roles, err := db.GetUserRolesAndPermissions(r.Context(), userId)
	if err != nil {
		utils.WriteError(w, http.StatusUnauthorized, "Database error", "code x")
		return
	}

	if err := utils.ValidateAccessToken(accessToken, permissions, roles); err != nil {
		utils.WriteError(w, http.StatusUnauthorized, "Password Reset Request Failed", err.Error())
		return
	}

	otp, err := utils.GenerateOtp()
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	cache := &models.CredentialResetCache{
		Otp:        otp,
		Tries:      3,
		Credential: input.Credential,
		Value:      input.Value,
	}

	cacheId := uuid.NewString()

	if err := db.RedisSet(r.Context(), cacheId, cache); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	if err := utils.SendOtp(otp); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	core.CaptureAudit(r.Context(), userpool, userId, userId, core.ActionUserUpdateCredentialRequest, (*core.AuditMetadata)(core.ExtractRequestMetadata(r)))

	response.Id = cacheId
	response.Message = "Otp Sent Successfully"
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)

}

// CredentialVerifyHandler godoc
// @Summary      Verify OTP for credential reset
// @Description  Verifies OTP and updates the requested credential (phone/email) for the logged-in user.
// @Tags         User-management
// @Accept       json
// @Produce      json
// @Param        input  body      models.UserCredentialVerifyRequest  true  "Credential reset verification request containing OTP and cache ID"
// @Success      200    {object}  map[string]string                   "Credential Reset Successful"
// @Failure      400    {object}  models.ErrorResponse                "Invalid request body, wrong OTP, or validation error"
// @Failure      401    {object}  models.ErrorResponse                "Unauthorized (missing/invalid ID-TOKEN or ACCESS-TOKEN)"
// @Failure      404    {object}  models.ErrorResponse                "OTP session not found or expired"
// @Failure      500    {object}  models.ErrorResponse                "Server or database error"
// @Router       /api/v1/users/credential/verify [post]
func CredentialVerifyHandler(w http.ResponseWriter, r *http.Request) {
	var input models.UserCredentialVerifyRequest

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		utils.WriteError(w, http.StatusMethodNotAllowed, "Invalid Method", "Use POST")
		return
	}

	idToken, accessToken := r.Header.Get("ID-TOKEN"), r.Header.Get("ACCESS-TOKEN")

	if idToken == "" || accessToken == "" {
		utils.WriteError(w, http.StatusUnauthorized, "Missing Headers", "ID-TOKEN / ACCESS-TOKEN is Missing!")
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

	userId, userpool, err := utils.ExtractUserIDFromIDToken(idToken)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Password Reset Request Failed", err.Error())
		return
	}

	permissions, roles, err := db.GetUserRolesAndPermissions(r.Context(), userId)
	if err != nil {
		utils.WriteError(w, http.StatusUnauthorized, "Database error", "code x")
		return
	}

	if err := utils.ValidateAccessToken(accessToken, permissions, roles); err != nil {
		utils.WriteError(w, http.StatusUnauthorized, "Password Reset Request Failed", err.Error())
		return
	}

	cache, err := db.RedisGet[models.CredentialResetCache](r.Context(), input.Id)
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

	var query string

	switch cache.Credential {
	case "phone":
		query = `UPDATE users SET phone=$1 WHERE id=$2`
	case "email":
		query = `UPDATE users SET email=$1 WHERE id=$2`
	default:
		utils.WriteError(w, http.StatusBadRequest, "Invalid Method", "use phone/email")
		return
	}

	cmdTag, err := db.GetDb().Exec(r.Context(), query, cache.Value, userId)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Database error", err.Error())
		return
	}

	if cmdTag.RowsAffected() == 0 {
		utils.WriteError(w, http.StatusNotFound, "No user Id found", "Unable to reset password")
		return
	}

	if err = db.RedisDel(r.Context(), input.Id+"CredResetRequest"); err != nil {
		log.Printf("Redis Del Failed %s", err.Error())
	}

	response := map[string]string{
		"message": "Credential Reset Successful",
	}

	core.CaptureAudit(r.Context(), userpool, userId, userId, core.ActionUserUpdateCredentialVerify, (*core.AuditMetadata)(core.ExtractRequestMetadata(r)))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)

}
