package repository

import (
	"fmt"
	"jwtRefresh/internal/models"
	"sync"
)

type UserRepository struct {
	mu    sync.RWMutex
	users map[string]models.User
}

func NewUserRepository() *UserRepository {
	return &UserRepository{
		users: make(map[string]models.User),
	}
}

func (r *UserRepository) Create(user models.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.users[user.Username]; exists {
		return fmt.Errorf("user already exists")
	}

	r.users[user.Username] = user
	return nil
}

func (r *UserRepository) FindByUsername(username string) (*models.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	user, exists := r.users[username]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}

	return &user, nil
}
