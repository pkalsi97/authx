package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pkalsi97/authx/internal/models"
)

var pool *pgxpool.Pool

type DBErrorResponse struct {
	Status  int
	Message string
}

func StartDb(url string) {
	var err error
	pool, err = pgxpool.New(context.Background(), url)
	if err != nil {
		log.Fatal("Unable to connect to Database:", err)
	}
	log.Printf("Database Connected")
}

func GetDb() *pgxpool.Pool {
	return pool
}

func CloseDB() {
	if pool != nil {
		pool.Close()
		log.Println("Database Connection closed")
	}
}

func QueryRowAndScan(ctx context.Context, query string, args []any, dest ...any) error {
	return pool.QueryRow(ctx, query, args...).Scan(dest...)
}

// MapDbError maps Postgres errors (or pgx wrapped errors) to HTTP-friendly responses
func MapDbError(err error) DBErrorResponse {
	if errors.Is(err, pgx.ErrNoRows) {
		return DBErrorResponse{Status: http.StatusNotFound, Message: "Record not found"}
	}

	re := regexp.MustCompile(`SQLSTATE\s*\(?(\w{5})\)?`)
	matches := re.FindStringSubmatch(err.Error())
	if len(matches) == 2 {
		code := matches[1]
		switch code {
		// --- Constraint Violations ---
		case "23505": // unique_violation
			return DBErrorResponse{Status: http.StatusBadRequest, Message: "Resource already exists"}
		case "23503": // foreign_key_violation
			return DBErrorResponse{Status: http.StatusBadRequest, Message: "Invalid reference"}
		case "23502": // not_null_violation
			return DBErrorResponse{Status: http.StatusBadRequest, Message: "Missing required field"}
		case "23514": // check_violation
			return DBErrorResponse{Status: http.StatusBadRequest, Message: "Invalid value"}

		// --- Serialization / Concurrency ---
		case "40001", "40P01": // serialization_failure / deadlock_detected
			return DBErrorResponse{Status: http.StatusConflict, Message: "Transaction conflict, please retry"}

		// --- Data Errors ---
		case "22001": // string_data_right_truncation
			return DBErrorResponse{Status: http.StatusBadRequest, Message: "Value too long"}
		case "22003": // numeric_value_out_of_range
			return DBErrorResponse{Status: http.StatusBadRequest, Message: "Numeric value out of range"}
		case "22007": // invalid_datetime_format
			return DBErrorResponse{Status: http.StatusBadRequest, Message: "Invalid datetime format"}
		case "22012": // division_by_zero
			return DBErrorResponse{Status: http.StatusBadRequest, Message: "Division by zero"}
		case "22018": // invalid_character_value_for_cast
			return DBErrorResponse{Status: http.StatusBadRequest, Message: "Invalid type cast"}
		case "22P02":
			return DBErrorResponse{Status: http.StatusBadRequest, Message: "invalid input syntax for type uuid"}

		// --- Syntax / Internal errors ---
		case "42601": // syntax_error
			return DBErrorResponse{Status: http.StatusInternalServerError, Message: "Database syntax error"}
		case "42703": // undefined_column
			return DBErrorResponse{Status: http.StatusInternalServerError, Message: "Database column not found"}
		case "42P01": // undefined_table
			return DBErrorResponse{Status: http.StatusInternalServerError, Message: "Database table not found"}

		// --- Authentication / Permission ---
		case "28000": // invalid_authorization_specification
			return DBErrorResponse{Status: http.StatusUnauthorized, Message: "Invalid database credentials"}
		case "42501": // insufficient_privilege
			return DBErrorResponse{Status: http.StatusForbidden, Message: "Insufficient database privileges"}

		// --- Default fallback for unhandled Postgres errors ---
		default:
			return DBErrorResponse{Status: http.StatusInternalServerError, Message: "Database error"}
		}
	}

	return DBErrorResponse{Status: http.StatusInternalServerError, Message: "Database error"}
}

func GetUserRolesAndPermissions(ctx context.Context, userID string) (roles []string, permissions []string, err error) {
	query := `
        SELECT r.name, r.permissions
        FROM roles r
        JOIN user_roles ur ON ur.role_id = r.id
        WHERE ur.user_id = $1
    `

	rows, err := pool.Query(ctx, query, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("database query error: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var r models.RoleAndPermissions
		var permJSON []byte

		if err := rows.Scan(&r.Name, &permJSON); err != nil {
			return nil, nil, fmt.Errorf("scan error: %w", err)
		}

		if permJSON != nil {
			if err := json.Unmarshal(permJSON, &r.Permissions); err != nil {
				return nil, nil, fmt.Errorf("json unmarshal error: %w", err)
			}
		}

		roles = append(roles, r.Name)
		permissions = append(permissions, r.Permissions...)
	}

	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return roles, permissions, nil
}
