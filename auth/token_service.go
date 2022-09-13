package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type Jwt string

type TokenService struct {
}

func (service *TokenService) CreateRefreshToken(subject string, session string) (string, error) {
	payload := map[string]interface{}{
		"sub": subject,
		"sid": session,
		"iat": time.Now().Unix(),
		"exp": time.Now().AddDate(1, 0, 0).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(payload))
	tokenString, err := token.SignedString([]byte("key"))

	return string(tokenString), err
}
