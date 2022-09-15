package auth

import (
	"errors"
	"time"

	. "github.com/Untanky/go-id/src"
	"github.com/golang-jwt/jwt/v4"
)

type Jwt string

type TokenService[Payload any] interface {
	Create(payload Payload) (string, error)
	Validate(token string) (Payload, error)
}

type RefreshTokenService struct {
	Secret Secret
}

func (service *RefreshTokenService) Create(payload map[string]interface{}) (string, error) {
	payload["iat"] = time.Now().Unix()
	payload["exp"] = time.Now().AddDate(1, 0, 0).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(payload))
	tokenString, err := token.SignedString(service.Secret.GetSecret())

	return string(tokenString), err
}

func (service *RefreshTokenService) Validate(tokenString string) (map[string]interface{}, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}

		return service.Secret.GetSecret(), nil
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
