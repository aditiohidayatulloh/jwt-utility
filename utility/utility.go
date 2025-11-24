package utility

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AccessClaims adalah struct untuk Access Token
type AccessClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	RoleID int32  `json:"role_id"`
	jwt.RegisteredClaims
}

// RefreshClaims adalah struct untuk Refresh Token
type RefreshClaims struct {
	UserID string `json:"user_id"`

	jwt.RegisteredClaims
}

// GenerateToken membuat token baru berdasarkan data user
// GenerateTokens menghasilkan Access Token dan Refresh Token baru
func GenerateTokens(expACToken, expRFToken int, roleID int32, userID, email string, jwtSecret []byte) (string, string, error) {
	// --- Access Token (AT) ---
	// Kedaluwarsa dalam 15 menit
	atExpiresAt := time.Now().Add(time.Minute * time.Duration(expACToken))

	atClaims := AccessClaims{
		UserID: userID,
		Email:  email,
		RoleID: roleID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(atExpiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   userID, // Subjek biasanya adalah ID pengguna
		},
	}

	// Buat token menggunakan HMAC SHA256
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	accessToken, err := at.SignedString(jwtSecret)
	if err != nil {
		return "", "", fmt.Errorf("gagal menandatangani access token: %w", err)
	}

	// --- Refresh Token (RT) ---
	// Kedaluwarsa dalam 7 hari
	rtExpiresAt := time.Now().Add(time.Hour * time.Duration(expRFToken))

	rtClaims := RefreshClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(rtExpiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   userID,
		},
	}

	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	refreshToken, err := rt.SignedString(jwtSecret)
	if err != nil {
		return "", "", fmt.Errorf("gagal menandatangani refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

// ValidateToken memvalidasi string token dan mengembalikan claims jika valid
// ValidateAccessToken memvalidasi Access Token dan mengembalikan claims jika valid
func ValidateAccessToken(tokenString string, jwtSecret []byte) (*AccessClaims, error) {
	claims := &AccessClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Memastikan metode penandatanganan benar
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("metode penandatanganan tak terduga: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil {
		// Tangani kesalahan parsing atau validasi
		// Misalnya: "token is expired" atau "signature is invalid"
		return nil, fmt.Errorf("access token tidak valid: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("access token tidak valid")
	}

	// Claims sekarang berisi data yang valid
	return claims, nil
}

func ValidateRefreshToken(tokenString string, jwtSecret []byte) (*RefreshClaims, error) {
	claims := &RefreshClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("metode penandatanganan tak terduga: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("refresh token tidak valid: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("refresh token tidak valid")
	}

	// Selain validasi di sini, di sistem yang reliable,
	// Anda harus MEMERIKSA TokenUUID ini di Redis/Database.

	return claims, nil
}
