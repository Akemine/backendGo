package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"crypto/rand"
	"encoding/base64"

	"os"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/rs/cors"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

var (
	oauth2Config *oauth2.Config
	tokenMutex   sync.RWMutex
	validToken   *oauth2.Token
	stateMutex   sync.RWMutex
	stateStore   = make(map[string]time.Time)
	db           *sql.DB
)

func generateRandomState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	fmt.Println("On appelle handleLogin")

	// Décodage du JSON
	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, "Erreur lors de la lecture du JSON", http.StatusBadRequest)
		return
	}

	if credentials.Email == "" || credentials.Password == "" {
		http.Error(w, "Email et mot de passe requis", http.StatusBadRequest)
		return
	}

	// Vérifier les identifiants dans la base de données
	if !verifyCredentials(credentials.Email, credentials.Password) {
		http.Error(w, "Identifiants invalides", http.StatusUnauthorized)
		return
	}

	state, err := generateRandomState()
	if err != nil {
		http.Error(w, "Erreur lors de la génération du state", http.StatusInternalServerError)
		return
	}

	stateMutex.Lock()
	stateStore[state] = time.Now().Add(5 * time.Minute)
	stateMutex.Unlock()

	url := oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	fmt.Println("On appelle handleCallback")
	fmt.Printf("URL de callback reçue : %s\n", r.URL.String())
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	stateMutex.Lock()
	expiryTime, exists := stateStore[state]
	delete(stateStore, state) // Supprime le state après utilisation
	stateMutex.Unlock()

	if !exists || time.Now().After(expiryTime) {
		http.Error(w, "State invalide ou expiré", http.StatusBadRequest)
		return
	}

	if code == "" {
		fmt.Println("Aucun code reçu dans l'URL")
		http.Error(w, "Code manquant", http.StatusBadRequest)
		return
	}

	token, err := oauth2Config.Exchange(context.Background(), code)
	if err != nil {
		fmt.Printf("Erreur lors de l'échange du code : %v\n", err)
		http.Error(w, "Erreur lors de l'authentification", http.StatusInternalServerError)
		return
	}

	

	// Stockez le token valide
	tokenMutex.Lock()
	validToken = token
	tokenMutex.Unlock()

	// Renvoyez le token au frontend
	w.Header().Set("Content-Type", "application/json")
	fmt.Println("token : ", token)
	json.NewEncoder(w).Encode(token)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	fmt.Println("On appelle handleLogout")

	// Vérifier si un token est présent dans l'en-tête Authorization
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Aucun token fourni", http.StatusBadRequest)
		return
	}

	bearerToken := strings.TrimPrefix(authHeader, "Bearer ")
	if bearerToken == "" {
		http.Error(w, "Token invalide 1", http.StatusBadRequest)
		return
	}

	tokenMutex.Lock()
	defer tokenMutex.Unlock()

	// Vérifier si le token fourni correspond au token stocké
	if validToken == nil || bearerToken != validToken.AccessToken {
		http.Error(w, "Token invalide ou déjà déconnecté", http.StatusBadRequest)
		return
	}

	// Invalider le token
	validToken = nil

	// Répondre avec un message de succès
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Déconnexion réussie")
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		// fmt.Println("authHeader : ", authHeader)
		if authHeader == "" {
			http.Error(w, "Autorisation manquante", http.StatusUnauthorized)
			return
		}

		bearerToken := strings.TrimPrefix(authHeader, "Bearer ")
		if bearerToken == "" {
			http.Error(w, "Token invalide", http.StatusUnauthorized)
			return
		}

		tokenMutex.RLock()
		token := validToken
		tokenMutex.RUnlock()

		if token == nil {
			http.Error(w, "Aucun token valide stocké", http.StatusUnauthorized)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Vérifier si le token est expiré ou ne correspond pas
		if token.Expiry.Before(time.Now()) || bearerToken != token.AccessToken {
			// fmt.Println("Token expiré ou ne correspondant pas, tentative de rafraîchissement")
			newToken, err := refreshToken(token)
			if err != nil {
				http.Error(w, "Impossible de rafraîchir le token", http.StatusUnauthorized)
				return
			}
			tokenMutex.Lock()
			validToken = newToken
			tokenMutex.Unlock()

			// Renvoyer une réponse avec le code d'état 401 et le nouveau token dans un en-tête
			w.Header().Set("X-New-Token", newToken.AccessToken)
			// fmt.Println("newToken.AccessToken : ", newToken.AccessToken)
			w.WriteHeader(http.StatusOK)
			fmt.Println("Token rafraîchi avec succès")
		}

		// Si le token est valide, passez à la prochaine fonction
		next.ServeHTTP(w, r)

	}
}

func handleProtectedRoute(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Route protégée accessible")
}

func main() {
	// Création d'un nouveau routeur
	mux := http.NewServeMux()

	// Ajout de vos routes
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/callback", handleCallback)
	mux.HandleFunc("/api/protected", authMiddleware(handleProtectedRoute))
	mux.HandleFunc("/logout", handleLogout) // Ajout de la nouvelle route

	// Configuration CORS
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
		ExposedHeaders:   []string{"X-New-Token"},
	})

	// Création du handler avec CORS
	handler := c.Handler(mux)

	// Démarrage du serveur
	fmt.Println("Serveur démarré sur http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", handler))

	go cleanupExpiredStates()
}

func cleanupExpiredStates() {
	for {
		time.Sleep(5 * time.Minute)
		now := time.Now()
		stateMutex.Lock()
		for state, expiry := range stateStore {
			if now.After(expiry) {
				delete(stateStore, state)
			}
		}
		stateMutex.Unlock()
	}
}

func refreshToken(token *oauth2.Token) (*oauth2.Token, error) {
	if token.RefreshToken == "" {
		return nil, fmt.Errorf("pas de refresh token disponible")
	}

	tokenSource := oauth2Config.TokenSource(context.Background(), token)
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("erreur lors du rafraîchissement du token: %v", err)
	}

	// Définir l'expiration du nouveau token à 10 secondes
	newToken.Expiry = time.Now().Add(10 * time.Second)

	return newToken, nil
}

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Erreur lors du chargement du fichier .env")
	}

	oauth2Config = &oauth2.Config{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		Scopes:       []string{"admin"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "http://localhost:9096/authorize",
			TokenURL: "http://localhost:9096/token",
		},
		RedirectURL: "http://localhost:8080/callback",
	}

	// Configuration de la connexion à la base de données
	dbinfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("DB_HOST"), os.Getenv("DB_PORT"), os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_NAME"))

	var dbErr error
	db, dbErr = sql.Open("postgres", dbinfo)
	if dbErr != nil {
		log.Fatal("Erreur lors de la connexion à la base de données : ", dbErr)
	}

	if err := db.Ping(); err != nil {
		log.Fatal("Erreur lors du ping de la base de données : ", err)
	}

	fmt.Println("Connexion à la base de données établie avec succès")
}

func verifyCredentials(email, password string) bool {
	var hashedPassword string
	err := db.QueryRow("SELECT password_hash FROM users WHERE email = $1", email).Scan(&hashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return false
		}
		log.Printf("Erreur lors de la récupération du mot de passe : %v", err)
		return false
	}

	// Comparer le mot de passe fourni avec le hash stocké
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}
