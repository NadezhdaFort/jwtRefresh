package services

import (
	"crypto/ed25519"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"jwtRefresh/pkg/tokens"
	"time"
)

type AuthService struct {
	JwtManager *tokens.JWTManager
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

var (
	AccessExpiresIn    = 15 * time.Minute
	RefreshExpiresIn   = 7 * 24 * time.Hour
	ErrKeyParsing      = fmt.Errorf("parsing error")
	ErrTokenGeneration = fmt.Errorf("token generation error")
	ErrSigning         = fmt.Errorf("signing error")
	ErrValidation      = fmt.Errorf("token validation errror")
)

func (a *AuthService) ValidateToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, ErrValidation
		}
		return a.PublicKey, nil
	},
		jwt.WithIssuer(a.JwtManager.Issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrValidation, err)
	}
	return token, nil
}

func (a *AuthService) GenerateTokens(username string) (string, string, error) {
	accessClaims := jwt.MapClaims{
		"sub": username,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(AccessExpiresIn).Unix(),
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodEdDSA, accessClaims)
	signedAccessToken, err := accessToken.SignedString(a.PrivateKey)
	if err != nil {
		return "", "", fmt.Errorf("%w: %s", ErrSigning, err)
	}

	refreshClaims := jwt.MapClaims{
		"sub": username,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(RefreshExpiresIn).Unix(),
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodEdDSA, refreshClaims)
	signedRefreshToken, err := refreshToken.SignedString(a.PrivateKey)
	if err != nil {
		return "", "", fmt.Errorf("%w: %s", ErrSigning, err)
	}

	return signedAccessToken, signedRefreshToken, nil
}
