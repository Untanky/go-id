package auth

import (
	"time"

	. "github.com/Untanky/go-id/src"
)

type TokenService[Payload any] interface {
	Create(payload Payload) (Jwt, error)
	Validate(token Jwt) (Payload, error)
}

type RefreshTokenService struct {
	Secret Secret
}

func (service *RefreshTokenService) Create(payload map[string]interface{}) (Jwt, error) {
	payload["iat"] = time.Now().Unix()
	payload["exp"] = time.Now().AddDate(1, 0, 0).Unix()

	token, err := CreateJwt(HS512, payload, string(service.Secret.GetSecret()))

	return token, err
}

func (service *RefreshTokenService) Validate(token Jwt) (map[string]interface{}, error) {
	payload, err := token.Payload()
	if err != nil {
		return nil, err
	}

	err = token.Validate(string(service.Secret.GetSecret()))
	if err != nil {
		return nil, err
	}

	return payload, nil
}
