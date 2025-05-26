package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"os"
	"home/spongedingus/workspace/chirpy/internal/database"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db *database.Queries
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
	
	mux.HandleFunc("GET /api/healthz", readinessHandler)
	mux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandler)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)
	mux.HandleFunc("POST /api/validate_chirp", apiCfg.validationHandler)

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
	cfg.fileserverHits.Store(0)
	w.WriteHeader(http.StatusOK)
}

func (cfg *apiConfig) validationHandler(w http.ResponseWriter, r *http.Request){
	type parameters struct {
		Body string `json:"body"`
	}

	type errorResponse struct {
		Error string `json:"error"`
	}

	type response struct {
		Valid bool `json:"valid"`
	}

	type CleanedResponse struct {
		CleanedBody string `json:"cleaned_body"`
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

	if len(params.Body) <= 140 {
		cleanedText := filterProfanity(params.Body)

		respBody := CleanedResponse{
		CleanedBody: cleanedText,
	}

	dat, marshalErr := json.Marshal(respBody)
		if marshalErr != nil {
			log.Printf("Error marshalling JSON: %s", marshalErr)
			w.WriteHeader(500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(dat)
		return
	}
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