package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type Jwt string

type TokenService struct {
	Secret []byte
}

func (service *TokenService) CreateRefreshToken(subject string, session string) (string, error) {
	payload := map[string]interface{}{
		"sub": subject,
		"sid": session,
		"iat": time.Now().Unix(),
		"exp": time.Now().AddDate(1, 0, 0).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(payload))
	tokenString, err := token.SignedString(service.Secret)

	return string(tokenString), err
}

func (service *TokenService) ValidateRefreshToken(tokenString string) (map[string]interface{}, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}

		return service.Secret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return map[string]interface{}(claims), nil
	} else {
		return nil, errors.New("invalid token")
	}
}
