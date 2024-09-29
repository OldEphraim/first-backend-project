package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/OldEphraim/webservers/internal/auth"
	"github.com/OldEphraim/webservers/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt" // Import bcrypt for hashing
)

// apiConfig holds any stateful, in-memory data
type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	jwtSecret      []byte // Add this line to define the jwtSecret field
	polkaKey       string // Add this line to define the PolkaKey field
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

type User struct {
	ID             uuid.UUID `json:"id"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Email          string    `json:"email"`
	HashedPassword string    `json:"-"` // This should not be exposed in the API response
	IsChirpyRed    bool      `json:"is_chirpy_red"`
}

type Queries struct {
	db *sql.DB
}

// New function to create a new Queries instance
func New(db *sql.DB) *Queries {
	return &Queries{db: db}
}

// Helper function to respond with error messages
func respondWithError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// Helper function to respond with JSON payloads
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(payload)
}

// Readiness handler function
func (cfg *apiConfig) readinessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// Metrics handler to return HTML metrics
func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {
	hits := cfg.fileserverHits.Load()
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<html><body><h1>Welcome, Chirpy Admin</h1><p>Chirpy has been visited %d times!</p></body></html>", hits)
}

// Reset handler to reset the hit count
func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK) // Only call this once.
	_, err := w.Write([]byte("Reset successful"))
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not reset users")
		return
	}
}

// CreateChirp inserts a new chirp into the database.
func (q *Queries) CreateChirp(ctx context.Context, body string, userID uuid.UUID) (Chirp, error) {
	row := q.db.QueryRowContext(ctx, `
        INSERT INTO chirps (body, user_id)
        VALUES ($1, $2) RETURNING id, created_at, updated_at`,
		body, userID)

	var chirp Chirp
	err := row.Scan(&chirp.ID, &chirp.CreatedAt, &chirp.UpdatedAt)
	if err != nil {
		return Chirp{}, err
	}

	chirp.Body = body
	chirp.UserID = userID
	return chirp, nil
}

func (q *Queries) GetAllChirps(ctx context.Context) ([]Chirp, error) {
	// SQL query to fetch all chirps
	rows, err := q.db.QueryContext(ctx, `
        SELECT id, body, user_id, created_at, updated_at 
        FROM chirps 
        ORDER BY created_at
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	chirpsMap := make(map[string]Chirp)
	var chirps []Chirp

	for rows.Next() {
		var chirp Chirp
		if err := rows.Scan(&chirp.ID, &chirp.Body, &chirp.UserID, &chirp.CreatedAt, &chirp.UpdatedAt); err != nil {
			return nil, err
		}

		// Check if the body is already in the map
		if _, exists := chirpsMap[chirp.Body]; !exists {
			chirpsMap[chirp.Body] = chirp
		}
	}

	// Convert the map values to a slice
	for _, chirp := range chirpsMap {
		chirps = append(chirps, chirp)
	}

	return chirps, nil
}

// GetChirpByID retrieves a single chirp by its ID from the database
func (q *Queries) GetChirpByID(ctx context.Context, chirpID uuid.UUID) (Chirp, error) {
	var chirp Chirp
	err := q.db.QueryRowContext(ctx, `
        SELECT id, created_at, updated_at, body, user_id
        FROM chirps
        WHERE id = $1
    `, chirpID).Scan(&chirp.ID, &chirp.CreatedAt, &chirp.UpdatedAt, &chirp.Body, &chirp.UserID)
	if err != nil {
		return Chirp{}, err
	}
	return chirp, nil
}

// Handler to create a new chirp
func (cfg *apiConfig) createChirpHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Received request at /api/chirps from createChirpHandler")
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Validate JWT
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid token")
		return
	}

	userID, err := auth.ValidateJWT(tokenString, string(cfg.jwtSecret))
	log.Printf("UserID from token: %v\n", userID) // Log userID to verify it's not null
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid or expired token")
		return
	}

	var input struct {
		Body   string    `json:"body"`
		UserID uuid.UUID `json:"user_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid input")
		return
	}

	if len(input.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}

	params := database.CreateChirpParams{
		Body:   input.Body,
		UserID: userID,
	}

	newChirp, err := cfg.dbQueries.CreateChirp(r.Context(), params)
	if err != nil {
		log.Printf("Error inserting chirp: %v\n", err)
		respondWithError(w, http.StatusInternalServerError, "Could not create chirp")
		return
	}

	chirp := Chirp{
		ID:        newChirp.ID,
		CreatedAt: newChirp.CreatedAt,
		UpdatedAt: newChirp.UpdatedAt,
		Body:      params.Body,
		UserID:    params.UserID,
	}

	respondWithJSON(w, http.StatusCreated, chirp)
}

// Handler to get all chirps ordered by created_at
func getChirpsHandler(cfg *apiConfig, w http.ResponseWriter, r *http.Request) {
	log.Println("Received request at /api/chirps from getChirpsHandler")

	if r.Method != http.MethodGet {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get the author_id query parameter
	authorID := r.URL.Query().Get("author_id")

	var authorUUID uuid.UUID
	var uuidParseErr error

	// Only parse authorID if it's provided
	if authorID != "" {
		authorUUID, uuidParseErr = uuid.Parse(authorID)
		if uuidParseErr != nil {
			log.Printf("Invalid UUID: %v", uuidParseErr)
			respondWithError(w, http.StatusBadRequest, "Invalid author ID")
			return
		}
	}

	// Get the sort query parameter, default to "asc"
	sortOrder := r.URL.Query().Get("sort")
	if sortOrder == "" {
		sortOrder = "asc" // Default to ascending order
	}

	// Query chirps based on author_id if provided, otherwise query all chirps
	if authorID != "" {
		// Assuming that GetChirpsByAuthorID returns a slice of a specific type
		chirpsByAuthor, err := cfg.dbQueries.GetChirpsByAuthorID(r.Context(), authorUUID)
		if err != nil {
			log.Printf("Error retrieving chirps by author ID: %v\n", err)
			respondWithError(w, http.StatusInternalServerError, "Could not retrieve chirps")
			return
		}

		// Sort chirps based on sort order
		if sortOrder == "desc" {
			sort.Slice(chirpsByAuthor, func(i, j int) bool {
				return chirpsByAuthor[i].CreatedAt.After(chirpsByAuthor[j].CreatedAt)
			})
		} else {
			// Default to ascending order
			sort.Slice(chirpsByAuthor, func(i, j int) bool {
				return chirpsByAuthor[i].CreatedAt.Before(chirpsByAuthor[j].CreatedAt)
			})
		}

		// Prepare the response for chirps by author
		chirpResponses := make([]struct {
			ID        string    `json:"id"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			Body      string    `json:"body"`
			UserID    string    `json:"user_id"`
		}, len(chirpsByAuthor))

		for i, chirp := range chirpsByAuthor {
			userID := chirp.UserID.String() // Convert to string if valid
			chirpResponses[i] = struct {
				ID        string    `json:"id"`
				CreatedAt time.Time `json:"created_at"`
				UpdatedAt time.Time `json:"updated_at"`
				Body      string    `json:"body"`
				UserID    string    `json:"user_id"`
			}{
				ID:        chirp.ID.String(),
				CreatedAt: chirp.CreatedAt,
				UpdatedAt: chirp.UpdatedAt,
				Body:      chirp.Body,
				UserID:    userID,
			}
		}

		respondWithJSON(w, http.StatusOK, chirpResponses)
		return
	}

	// If author_id is not provided, query all chirps
	chirps, err := cfg.dbQueries.GetAllChirps(r.Context())
	if err != nil {
		log.Printf("Error retrieving chirps: %v\n", err)
		respondWithError(w, http.StatusInternalServerError, "Could not retrieve chirps")
		return
	}

	// Sort chirps based on sort order
	if sortOrder == "desc" {
		sort.Slice(chirps, func(i, j int) bool {
			return chirps[i].CreatedAt.After(chirps[j].CreatedAt)
		})
	} else {
		// Default to ascending order
		sort.Slice(chirps, func(i, j int) bool {
			return chirps[i].CreatedAt.Before(chirps[j].CreatedAt)
		})
	}

	// Prepare the response structure for all chirps
	var chirpResponses []struct {
		ID        string    `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserID    string    `json:"user_id"`
	}

	// Map chirps to the expected response format
	for _, chirp := range chirps {
		userID := chirp.UserID.String() // Convert to string if valid
		chirpResponses = append(chirpResponses, struct {
			ID        string    `json:"id"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			Body      string    `json:"body"`
			UserID    string    `json:"user_id"`
		}{
			ID:        chirp.ID.String(),
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    userID,
		})
	}

	// Return a 404 status if no chirps are found
	if len(chirpResponses) == 0 {
		respondWithError(w, http.StatusNotFound, "Chirp not found")
		return
	}

	respondWithJSON(w, http.StatusOK, chirpResponses)
}

// deleteChirpHandler handles the deletion of a chirp.
func deleteChirpHandler(cfg *apiConfig, w http.ResponseWriter, r *http.Request) {
	// Validate JWT
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid token")
		return
	}

	userID, err := auth.ValidateJWT(tokenString, string(cfg.jwtSecret))
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid or expired token")
		return
	}

	// Extract chirp ID from URL (assuming you use something like /api/chirps/{id})
	chirpID := strings.TrimPrefix(r.URL.Path, "/api/chirps/")
	if chirpID == "" {
		respondWithError(w, http.StatusBadRequest, "Invalid chirp ID")
		return
	}

	chirpUUID, err := uuid.Parse(chirpID)
	if err != nil {
		// Handle error, perhaps return an appropriate response or log it
		log.Printf("Invalid UUID: %v", err)
		return
	}

	// Check if the chirp exists and if the user is the author.
	authorID, err := cfg.dbQueries.GetChirpAuthorID(r.Context(), chirpUUID)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "Chirp not found")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	// Check if the user is the author
	if authorID != userID {
		respondWithError(w, http.StatusForbidden, "You are not the author of this chirp")
		return
	}

	// Delete the chirp
	err = cfg.dbQueries.DeleteChirp(r.Context(), chirpUUID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	// Return 204 No Content
	w.WriteHeader(http.StatusNoContent)
}

// createUserHandler handles user registration
func createUserHandler(cfg *apiConfig, w http.ResponseWriter, r *http.Request) {
	log.Println("Received request at /api/users from createUserHandler")
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid input")
		return
	}

	// Hash the password using bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v\n", err)
		respondWithError(w, http.StatusInternalServerError, "Could not hash password")
		return
	}

	params := database.CreateUserParams{
		Email:          input.Email,
		HashedPassword: string(hashedPassword), // Store the hashed password
	}

	newUser, err := cfg.dbQueries.CreateUser(r.Context(), params)
	if err != nil {
		log.Printf("Error inserting user: %v\n", err)
		respondWithError(w, http.StatusInternalServerError, "Could not create user")
		return
	}

	userResponse := User{
		ID:             newUser.ID,
		CreatedAt:      newUser.CreatedAt,
		UpdatedAt:      newUser.UpdatedAt,
		Email:          newUser.Email,
		HashedPassword: newUser.HashedPassword, // Exclude this from the response in the future
		IsChirpyRed:    newUser.IsChirpyRed,
	}

	respondWithJSON(w, http.StatusCreated, userResponse)
}

func (cfg *apiConfig) handleLogin(w http.ResponseWriter, r *http.Request) {
	log.Println("Received request at /api/login from handleLogin")
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var input struct {
		Email            string `json:"email"`
		Password         string `json:"password"`
		ExpiresInSeconds *int   `json:"expires_in_seconds,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid input")
		return
	}

	// Set default expiration time
	expiration := 1 * time.Hour
	if input.ExpiresInSeconds != nil {
		if *input.ExpiresInSeconds > 3600 {
			expiration = 1 * time.Hour
		} else {
			expiration = time.Duration(*input.ExpiresInSeconds) * time.Second
		}
	}

	// Look up the user by email
	user, err := cfg.dbQueries.GetUserByEmail(r.Context(), input.Email)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	// Inside your login handler
	refreshToken, err := auth.MakeRefreshToken(user.ID, expiration)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not create refresh token")
		return
	}

	// Save the refresh token to the database with expiration
	_, err = cfg.dbQueries.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token:     refreshToken.Token,
		UserID:    refreshToken.UserID,
		ExpiresAt: refreshToken.ExpiresAt,
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not save refresh token")
		return
	}

	accessToken, err := auth.MakeJWT(user.ID, string(cfg.jwtSecret), expiration)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not create token")
		return
	}

	// Check the password against the hashed password
	if err := auth.CheckPasswordHash(input.Password, user.HashedPassword); err != nil {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"id":            user.ID,
		"created_at":    user.CreatedAt,
		"updated_at":    user.UpdatedAt,
		"email":         user.Email,
		"token":         accessToken,
		"refresh_token": refreshToken,
		"is_chirpy_red": user.IsChirpyRed,
	})
}

func (cfg *apiConfig) refreshHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Received request at /api/refresh")

	// Extract the refresh token from the Authorization header
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid token")
		return
	}
	tokenString := authHeader[7:] // Remove "Bearer "

	// Retrieve the refresh token details from the database
	refreshToken, err := cfg.dbQueries.GetUserFromRefreshToken(r.Context(), tokenString)
	if err != nil {
		log.Println("Token not found in database:", err)

		// Attempt to parse the token as a map if retrieval failed
		var tokenData map[string]string

		// Remove the "map[" prefix and "]" suffix
		trimmed := strings.TrimPrefix(tokenString, "map[")
		trimmed = strings.TrimSuffix(trimmed, "]")

		// Split by space to get key-value pairs
		pairs := strings.Fields(trimmed)

		// Create a map to hold the results
		tokenData = make(map[string]string)

		// Loop through each pair
		for _, pair := range pairs {
			// Split by colon to separate key and value
			parts := strings.SplitN(pair, ":", 2)
			if len(parts) == 2 {
				key := parts[0]
				value := parts[1]

				// Handle special cases for value types
				if value == "<nil>" {
					value = ""
				}

				tokenData[key] = value
			}
		}

		// Check if the "Token" field exists and is a valid string
		if token, ok := tokenData["Token"]; ok {
			// Retrieve the refresh token details again using the extracted token
			refreshToken, err = cfg.dbQueries.GetUserFromRefreshToken(r.Context(), token)
			if err != nil {
				respondWithError(w, http.StatusUnauthorized, "Invalid or expired token")
				return
			}
		} else {
			respondWithError(w, http.StatusUnauthorized, "Missing or invalid token")
			return
		}
	}

	// Check if the original token is expired
	if time.Now().After(refreshToken.ExpiresAt) {
		respondWithError(w, http.StatusUnauthorized, "Token has expired")
		return
	}

	// Generate a new JWT access token
	newAccessToken, err := auth.MakeJWT(refreshToken.UserID, string(cfg.jwtSecret), time.Hour) // 1 hour expiry
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not generate access token")
		return
	}

	// Respond with the new access token
	respondWithJSON(w, http.StatusOK, map[string]string{
		"token": newAccessToken,
	})
}

func (cfg *apiConfig) revokeHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Received request at /api/revoke")

	// Extract the refresh token from the Authorization header
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid token")
		return
	}
	tokenString := authHeader[7:] // Remove "Bearer "

	// Retrieve the refresh token details from the database
	refreshToken, err := cfg.dbQueries.GetUserFromRefreshToken(r.Context(), tokenString)
	if err != nil {
		log.Println("Token not found in database:", err)

		// Attempt to parse the token as a map if retrieval failed
		var tokenData map[string]string

		// Remove the "map[" prefix and "]" suffix
		trimmed := strings.TrimPrefix(tokenString, "map[")
		trimmed = strings.TrimSuffix(trimmed, "]")

		// Split by space to get key-value pairs
		pairs := strings.Fields(trimmed)

		// Create a map to hold the results
		tokenData = make(map[string]string)

		// Loop through each pair
		for _, pair := range pairs {
			// Split by colon to separate key and value
			parts := strings.SplitN(pair, ":", 2)
			if len(parts) == 2 {
				key := parts[0]
				value := parts[1]

				// Handle special cases for value types
				if value == "<nil>" {
					value = ""
				}

				tokenData[key] = value
			}
		}

		// Check if the "Token" field exists and is a valid string
		if token, ok := tokenData["Token"]; ok {
			// Retrieve the refresh token details again using the extracted token
			refreshToken, err = cfg.dbQueries.GetUserFromRefreshToken(r.Context(), token)
			if err != nil {
				respondWithError(w, http.StatusUnauthorized, "Invalid or expired token")
				return
			}
		} else {
			respondWithError(w, http.StatusUnauthorized, "Missing or invalid token")
			return
		}
	}

	// Revoke the refresh token by updating the revoked_at timestamp
	err = cfg.dbQueries.RevokeRefreshToken(r.Context(), refreshToken.Token)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not revoke token")
		return
	}

	// Respond with 204 No Content
	w.WriteHeader(http.StatusNoContent)
}

// updateUserHandler handles user updates
func updateUserHandler(cfg *apiConfig, w http.ResponseWriter, r *http.Request) {
	log.Println("Received request at /api/users from updateUserHandler")
	if r.Method != http.MethodPut {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Validate JWT
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid token")
		return
	}

	userID, err := auth.ValidateJWT(tokenString, string(cfg.jwtSecret))
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid or expired token")
		return
	}

	var input struct {
		Email    string `json:"email"`
		Password string `json:"password,omitempty"` // Optional
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid input")
		return
	}

	// Prepare the update parameters
	params := database.UpdateUserParams{
		Column1: input.Email,
		Column2: input.Password,
		ID:      userID,
	}

	if input.Email != "" {
		params.Column1 = input.Email
	}

	if input.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("Error hashing password: %v\n", err)
			respondWithError(w, http.StatusInternalServerError, "Could not hash password")
			return
		}
		params.Column2 = string(hashedPassword) // Store the hashed password
	}

	if _, err := cfg.dbQueries.UpdateUser(r.Context(), params); err != nil {
		log.Printf("Error updating user: %v\n", err)
		respondWithError(w, http.StatusInternalServerError, "Could not update user")
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"message": "User updated successfully", "email": input.Email})
}

// chirpHandler checks the request method and calls the appropriate handler.
func (cfg *apiConfig) chirpHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodDelete:
		deleteChirpHandler(cfg, w, r) // Call the handler for DELETE requests
	case http.MethodGet:
		getChirpsHandler(cfg, w, r) // Call the handler for GET requests
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (cfg *apiConfig) usersHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		createUserHandler(cfg, w, r) // Call the handler for POST requests
	case http.MethodPut:
		updateUserHandler(cfg, w, r) // Call the handler for PUT requests
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// Handler for Polka webhooks
func (cfg *apiConfig) polkaWebhookHandler(w http.ResponseWriter, r *http.Request) {
	var reqBody struct {
		Event string `json:"event"`
		Data  struct {
			UserID string `json:"user_id"`
		} `json:"data"`
	}

	// Parse the request body
	err := json.NewDecoder(r.Body).Decode(&reqBody)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Extract the API key from the headers
	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil || apiKey != cfg.polkaKey {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// If the event is not "user.upgraded", return 204 No Content
	if reqBody.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Parse the user ID as UUID
	userUUID, err := uuid.Parse(reqBody.Data.UserID)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	// Upgrade the user to Chirpy Red
	err = cfg.dbQueries.UpgradeUserToChirpyRed(r.Context(), userUUID)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "User not found")
			return
		}
		log.Printf("Error upgrading user: %v\n", err)
		respondWithError(w, http.StatusInternalServerError, "Could not upgrade user")
		return
	}

	// Respond with 204 No Content if successful
	w.WriteHeader(http.StatusNoContent)
}

// Main function
func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Database connection setup
	connStr := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	cfg := apiConfig{
		dbQueries: database.New(db),
		jwtSecret: []byte(os.Getenv("JWT_SECRET")),
		polkaKey:  os.Getenv("POLKA_KEY"),
	}

	// Routes for chirps
	http.HandleFunc("/api/chirps", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			cfg.createChirpHandler(w, r) // Handle POST requests for creating a chirp
		} else {
			cfg.chirpHandler(w, r) // Handle GET, PUT, DELETE, etc.
		}
	})

	http.HandleFunc("/api/users", cfg.usersHandler)
	http.HandleFunc("/api/login", cfg.handleLogin)
	http.HandleFunc("/ready", cfg.readinessHandler)
	http.HandleFunc("/metrics", cfg.metricsHandler)
	http.HandleFunc("/admin/reset", cfg.resetHandler)
	http.HandleFunc("/api/refresh", cfg.refreshHandler)
	http.HandleFunc("/api/revoke", cfg.revokeHandler)
	http.HandleFunc("/api/polka/webhooks", cfg.polkaWebhookHandler)

	// Serve static files from the "/app" path, strip "/app" from the request path
	fileServer := http.FileServer(http.Dir("."))
	http.Handle("/app/", http.StripPrefix("/app", fileServer))

	// Start the server
	log.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
