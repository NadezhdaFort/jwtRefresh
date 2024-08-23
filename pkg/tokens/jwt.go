package tokens

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

var (
	ErrKeyParsing      = fmt.Errorf("parsing error")
	ErrTokenGeneration = fmt.Errorf("token generation error")
	ErrSigning         = fmt.Errorf("signing error")
	ErrValidation      = fmt.Errorf("token validation errror")
)

type JWTManager struct {
	Issuer           string
	accessExpiresIn  time.Duration
	refreshExpiresIn time.Duration
	publicKey        interface{}
	privateKey       interface{}
}

func NewJWTManager(issuer string, accessExpiresIn time.Duration, refreshExpiresIn time.Duration, publicKey, privateKey []byte) (*JWTManager, error) {
	pubKey, err := jwt.ParseEdPublicKeyFromPEM(publicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyParsing, err)
	}

	privKey, err := jwt.ParseEdPrivateKeyFromPEM(privateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyParsing, err)
	}

	return &JWTManager{
		Issuer:           issuer,
		accessExpiresIn:  accessExpiresIn,
		refreshExpiresIn: refreshExpiresIn,
		publicKey:        pubKey,
		privateKey:       privKey,
	}, nil
}
