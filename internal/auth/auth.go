package auth

import (
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"

	"net/http"
	"strings"

	"crypto/rand"
	"encoding/base64"
	"fmt"
)

type RefreshToken struct {
	Token     string     `db:"token"`
	CreatedAt time.Time  `db:"created_at"`
	UpdatedAt time.Time  `db:"updated_at"`
	UserID    uuid.UUID  `db:"user_id"`
	ExpiresAt time.Time  `db:"expires_at"`
	RevokedAt *time.Time `db:"revoked_at"` // Pointer to allow null value
}

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// CheckPasswordHash compares a password with a hash
func CheckPasswordHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// MakeJWT creates a new JWT token for the user.
func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	claims := &jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
		Subject:   userID.String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(tokenSecret))
}

// ValidateJWT validates the given token string and returns the user ID if valid.
func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.NewValidationError("invalid signing method", jwt.ValidationErrorMalformed)
		}
		return []byte(tokenSecret), nil
	})

	if err != nil || !token.Valid {
		return uuid.Nil, err
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return uuid.Nil, jwt.NewValidationError("invalid claims", jwt.ValidationErrorClaimsInvalid)
	}

	return uuid.Parse(claims.Subject)
}

// GetBearerToken extracts the token string from the Authorization header.
func GetBearerToken(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", jwt.NewValidationError("missing authorization header", jwt.ValidationErrorMalformed)
	}

	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return "", jwt.NewValidationError("invalid authorization header format", jwt.ValidationErrorMalformed)
	}

	fmt.Println("This is the authorization header in the getBearerToken function", authHeader)
	return strings.TrimSpace(authHeader[len(prefix):]), nil
}

func MakeRefreshToken(userID uuid.UUID, duration time.Duration) (RefreshToken, error) {
	token := make([]byte, 32) // 256 bits
	_, err := rand.Read(token)
	if err != nil {
		return RefreshToken{}, err
	}

	now := time.Now()
	expiresAt := now.Add(duration)

	// Use Base64 encoding for the token
	encodedToken := base64.StdEncoding.EncodeToString(token)

	return RefreshToken{
		Token:     encodedToken,
		CreatedAt: now,
		UpdatedAt: now,
		UserID:    userID,
		ExpiresAt: expiresAt,
		RevokedAt: nil, // or set as needed
	}, nil
}

// GetAPIKey extracts the API key from the Authorization header
func GetAPIKey(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("authorization header not found")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "apikey" {
		return "", errors.New("invalid authorization format")
	}

	return strings.TrimSpace(parts[1]), nil
}
