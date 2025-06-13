package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"home/spongedingus/workspace/chirpy/internal/auth"
	"home/spongedingus/workspace/chirpy/internal/database"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db *database.Queries
	jwtSecret string
}

type User struct {
	ID		uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email	string		`json:"email"`
}

type loginResponse struct {
	ID		uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email	string		`json:"email"`
	Token	string		`json:"token"`
	RefreshToken string	`json:"refresh_token"`
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
	}

	dbQueries := database.New(db)

	apiCfg := &apiConfig{
		db: dbQueries,
		jwtSecret: os.Getenv("JWT_SECRET"),
	}

	mux := http.NewServeMux()
	
	fileServer := http.FileServer(http.Dir("."))
	handler := http.StripPrefix("/app", fileServer)

	mux.Handle("/app", apiCfg.middlewareMetricsInc(handler))
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(handler))
	
	mux.HandleFunc("/api/healthz", readinessHandler)
	mux.HandleFunc("/admin/metrics", apiCfg.metricsHandler)
	mux.HandleFunc("/admin/reset", apiCfg.resetHandler)
	mux.HandleFunc("/api/users", apiCfg.postHandler)
	mux.HandleFunc("POST /api/chirps", apiCfg.chirpsHandler)
	mux.HandleFunc("GET /api/chirps", apiCfg.getChirpsHandler)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpHandler)
	mux.HandleFunc("POST /api/login", apiCfg.loginHandler)
	mux.HandleFunc("POST /api/refresh", apiCfg.refreshHandler)
	mux.HandleFunc("POST /api/revoke", apiCfg.revokeHandler)
	mux.HandleFunc("PUT /api/users", apiCfg.updateEmailPasswordHandler)

	server := http.Server{
		Addr:	":8080",
		Handler: mux,
	}

	err = server.ListenAndServe()
	if err != nil {
		fmt.Println(err)
	}
}

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	hits := cfg.fileserverHits.Load()
	template := `<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`
	w.Write([]byte(fmt.Sprintf(template, hits)))
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	platform := os.Getenv("PLATFORM")
	if platform != "dev" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := cfg.db.DeleteAllUsers(r.Context())
	if err != nil {
		http.Error(w, "Could not delete users", http.StatusInternalServerError)
		return
	}

	cfg.fileserverHits.Store(0)
	w.WriteHeader(http.StatusOK)
}

func (cfg *apiConfig) chirpsHandler(w http.ResponseWriter, r *http.Request){

	ctx := r.Context()
	
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorized Request"))
		return
	}

	userID, err := auth.ValidateJWT(tokenString, cfg.jwtSecret)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorized User"))
		return
	}

	type parameters struct {
		Body string `json:"body"`
		UserID string `json:"user_id"`
	}

	type errorResponse struct {
		Error string `json:"error"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)

	if err != nil {
		respBody := errorResponse{
			Error: "Error just cause",
		}
		dat, marshalErr := json.Marshal(respBody)
		if marshalErr != nil {
			log.Printf("Error marshalling JSON: %s", marshalErr)
			w.WriteHeader(500)
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		w.Write(dat)
		return	
	}

	if len(params.Body) > 140 {
		respBody := errorResponse{
			Error: "Chirp is too long",
		}

		dat, marshalErr := json.Marshal(respBody)
		if marshalErr != nil {
			log.Printf("Error marshalling JSON: %s", marshalErr)
			w.WriteHeader(500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		w.Write(dat)
		return
	}

	cleanedBody := filterProfanity(params.Body)

	chirpParams := database.CreateChirpParams{
		ID:			uuid.New(),
		CreatedAt:	time.Now().UTC(),
		UpdatedAt:	time.Now().UTC(),
		Body:		cleanedBody,
		UserID:		uuid.NullUUID{UUID: userID, Valid: true},
	}

	chirp, err := cfg.db.CreateChirp(ctx, chirpParams)

	if err != nil {
		log.Printf("CreateChirp failed: %v", err)
		http.Error(w, "Unable to create Chirp", http.StatusInternalServerError)
		return
	}

	type chirpResponse struct {
    ID        uuid.UUID `json:"id"`
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
    Body      string    `json:"body"`
    UserID    uuid.UUID `json:"user_id"`
	}


	resp := chirpResponse{
    	ID:        chirp.ID,
    	CreatedAt: chirp.CreatedAt,
    	UpdatedAt: chirp.UpdatedAt,
    	Body:      chirp.Body,
    	UserID:    chirp.UserID.UUID,
	}
		
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	json.NewEncoder(w).Encode(resp)
}


func filterProfanity(text string) string {
	words := strings.Split(text, " ")
	for index, word := range words {
		if strings.ToLower(word) == "kerfuffle" || strings.ToLower(word) == "sharbert" || strings.ToLower(word) == "fornax" {
			words[index] = "****"
		}
	}
	return strings.Join(words, " ")
}

func (cfg *apiConfig) postHandler(w http.ResponseWriter, r *http.Request){
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	type userRequest struct {
		Password string `json:"password"`
		Email string `json:"email"`
	}

	var params userRequest
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&params)

	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	createUser := database.CreateUserParams{
		HashedPassword: hashedPassword,
		Email: params.Email,
	}

	fmt.Printf("About to create user - Email: %s, HashedPassword length: %d\n", 
    createUser.Email, len(createUser.HashedPassword))

	user, err := cfg.db.CreateUser(r.Context(), createUser)
	if err != nil {
		fmt.Printf("Database error: %v\n", err)
		http.Error(w, "Could not create user", http.StatusInternalServerError)
		return
	}

	res := User{
		ID:		user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email:	user.Email,
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(res)
}

func (cfg *apiConfig) loginHandler(w http.ResponseWriter, r *http.Request){
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	type userRequest struct {
		Password string `json:"password"`
		Email string `json:"email"`
		
	}

	var params userRequest
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&params)

	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	user, err := cfg.db.GetUserByEmail(r.Context(), params.Email)
	if err != nil {
		fmt.Printf("Database error: %v\n", err)
		http.Error(w, "Incorrect email or password", http.StatusUnauthorized)
		return
	}

	err = auth.CheckPasswordHash(user.HashedPassword, params.Password)
	if err != nil {
		http.Error(w, "Incorrect email or password", http.StatusUnauthorized)
		return
	}

	expiresInDuration := time.Hour

	token, err := auth.MakeJWT(user.ID, cfg.jwtSecret, expiresInDuration)
	if err != nil {
		http.Error(w, "failed to create token", http.StatusInternalServerError)
		return
	}

	refreshtoken, err := auth.MakeRefreshToken()
	if err != nil {
		http.Error(w, "Failed to create refresh token", http.StatusInternalServerError)
		return
	}

	fmt.Printf("Created refresh token: %s\n", refreshtoken)

	_, err = cfg.db.CreateRefreshToken(context.Background(), database.CreateRefreshTokenParams{
		Token: refreshtoken,
		UserID: user.ID,
		ExpiresAt: time.Now().Add(60 * 24 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		RevokedAt: sql.NullTime{Valid: false},
	})

	if err != nil {
		http.Error(w, "Failed to create refresh token", http.StatusInternalServerError)
		return
	}

	res := loginResponse{
		ID:		user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email:	user.Email,
		Token: token,
		RefreshToken: refreshtoken,
	}

	fmt.Printf("Login response: %+v\n", res)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(res)
}

func (cfg *apiConfig) getChirpsHandler(w http.ResponseWriter, r *http.Request){
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	allChirps, err := cfg.db.RetrieveChirps(r.Context())
	if err != nil {
		http.Error(w, "Could not get chirps", http.StatusInternalServerError)
		return
	}

	type chirpResponse struct {
    ID        uuid.UUID `json:"id"`
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
    Body      string    `json:"body"`
    UserID    uuid.UUID `json:"user_id"`
	}

	var responses []chirpResponse

	for _, chirp := range allChirps {
		resp := chirpResponse{
    	ID:        chirp.ID,
    	CreatedAt: chirp.CreatedAt,
    	UpdatedAt: chirp.UpdatedAt,
    	Body:      chirp.Body,
    	UserID:    chirp.UserID.UUID,
	}
	
		responses = append(responses, resp)
	}

	json.NewEncoder(w).Encode(responses)
}

func (cfg *apiConfig) getChirpHandler(w http.ResponseWriter, r *http.Request){
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusInternalServerError)
		return
	}

	chirps, err := cfg.db.RetrieveChirps(r.Context())
	if err != nil {
		http.Error(w, "Could not get chirp", http.StatusInternalServerError)
	}

	type chirpResponse struct {
		ID			uuid.UUID	`json:"id"`
		CreatedAt	time.Time	`json:"created_at"`
		UpdatedAt	time.Time	`json:"updated_at"`
		Body		string		`json:"body"`
		UserID		uuid.UUID	`json:"user_id"`
	}

	chirpID := r.PathValue("chirpID")
	
	for _, chirp := range chirps {
		if chirp.ID.String() == chirpID {
			resp := chirpResponse{
				ID:			chirp.ID,
				CreatedAt:	chirp.CreatedAt,
				UpdatedAt:	chirp.UpdatedAt,
				Body:		chirp.Body,
				UserID:		chirp.UserID.UUID,
			}

			json.NewEncoder(w).Encode(resp)
			return
		}
	}

	http.Error(w, "Chirp not found", http.StatusNotFound)
}

func (cfg *apiConfig) refreshHandler(w http.ResponseWriter, r *http.Request){
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, "Could not extract refresh token", http.StatusInternalServerError)
		return
	}

	fmt.Printf("Looking for refresh token: %s\n", refreshToken)

	user, err := cfg.db.GetUserFromRefreshToken(context.Background(), refreshToken)
	if err != nil {
		http.Error(w, "Refresh token is expired or doesn't exist", http.StatusUnauthorized)
		return
	}

	token, err := auth.MakeJWT(user.ID, cfg.jwtSecret, time.Hour)
	if err != nil {
		http.Error(w, "failed to create token", http.StatusUnauthorized)
		return
	}

	response := map[string]string{
		"token": token,
}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func (cfg * apiConfig) revokeHandler(w http.ResponseWriter, r *http.Request){
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, "Could not extract refresh token", http.StatusInternalServerError)
		return
	}

	now := time.Now()
	params := database.RevokeRefreshTokenParams{
		RevokedAt: sql.NullTime{Time: time.Now(), Valid: true},
		UpdatedAt: now,
		Token: refreshToken,
	}

	err = cfg.db.RevokeRefreshToken(r.Context(), params)
	if err != nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) updateEmailPasswordHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != "PUT" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorized Request"))
		return
	}

	userID, err := auth.ValidateJWT(tokenString, cfg.jwtSecret)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorized User"))
		return
	}

	type parameters struct {
		Email	string	`json:"email"`
		Password	string	`json:"password"`
	}

	type errorResponse struct {
		Error string `json:"error"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)

	if err != nil {
		respBody := errorResponse{
			Error: fmt.Sprintf("Error unmarshalling JSON: %s", err),
		}

		dat, marshalErr := json.Marshal(respBody)
		if marshalErr != nil {
			log.Printf("Error marshalling JSON: %s", marshalErr)
			w.WriteHeader(500)
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		w.Write(dat)
		return	
	}

	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	updateUser := database.UpdateUserParams{
		HashedPassword: hashedPassword,
		Email: params.Email,
		ID: userID,
	}

	fmt.Printf("About to update user - Email: %s, HashedPassword length: %d\n", 
    updateUser.Email, len(updateUser.HashedPassword))

	user, err := cfg.db.UpdateUser(r.Context(), updateUser)
	if err != nil {
		fmt.Printf("Database error: %v\n", err)
		http.Error(w, "Could not create user", http.StatusInternalServerError)
		return
	}

	res := User{
		ID:		user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email:	user.Email,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(res)
}