package main

import (
	"crypto/ed25519"

	"github.com/gorilla/mux"
	"jwtRefresh/internal/handlers"
	"jwtRefresh/internal/repository"
	"jwtRefresh/internal/services"
	"jwtRefresh/pkg/tokens"

	"log"
	"net/http"
)

func main() {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)

	jwtManager, _ := tokens.NewJWTManager("example.com", 15*60, 24*60*7, publicKey, privateKey)

	authService := services.AuthService{
		JwtManager: jwtManager,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}

	userRepo := repository.NewUserRepository()
	userHandler := handlers.UserHandler{AuthService: authService, UserRepository: *userRepo}

	r := mux.NewRouter()
	r.HandleFunc("/register", userHandler.Register).Methods("POST")
	r.HandleFunc("/login", userHandler.Login).Methods("POST")

	log.Println("Server is running on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
