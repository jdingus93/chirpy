package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"home/spongedingus/workspace/chirpy/internal/database"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db *database.Queries
}

type User struct {
	ID		uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email	string		`json:"email"`
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
	}

	dbQueries := database.New(db)

	apiCfg := &apiConfig{db: dbQueries}

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

	type parameters struct {
		Body string `json:"body"`
		UserID string `json:"user_id"`
	}

	type errorResponse struct {
		Error string `json:"error"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)

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

	uid, err := uuid.Parse(params.UserID)
	if err != nil {
		http.Error(w, "Invalid user_id", http.StatusBadRequest)
		return
	}
	nullUID := uuid.NullUUID{UUID: uid, Valid: true}

	chirpParams := database.CreateChirpParams{
		ID:			uuid.New(),
		CreatedAt:	time.Now().UTC(),
		UpdatedAt:	time.Now().UTC(),
		Body:		cleanedBody,
		UserID:		nullUID,
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
		Email string `json:"email"`
	}

	var params userRequest
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&params)

	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	user, err := cfg.db.CreateUser(r.Context(), params.Email)
	if err != nil {
		log.Println("error creating user:", err)
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