package handlers

import (
	"encoding/json"
	"jwtRefresh/internal/models"
	"jwtRefresh/internal/repository"
	"jwtRefresh/internal/services"
	"net/http"
)

type UserHandler struct {
	AuthService    services.AuthService
	UserRepository repository.UserRepository
}

func (h *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	var user models.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	err := h.UserRepository.Create(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (h *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	var user models.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	storedUser, err := h.UserRepository.FindByUsername(user.Username)
	if err != nil || storedUser.Password != user.Password {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	accessToken, refreshToken, err := h.AuthService.GenerateTokens(user.Username)
	if err != nil {
		http.Error(w, "Error generating tokens", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"access_token": accessToken, "refresh_token": refreshToken})
}
