package auth

import (
	"time"
)

type TokenService[Payload any] interface {
	Create(payload Payload) (Jwt, error)
	Validate(token Jwt) (Payload, error)
}

type RefreshTokenService struct {
	jwtService *JwtService
}

func (service *RefreshTokenService) Init(jwtService *JwtService) {
	service.jwtService = jwtService
}

func (service *RefreshTokenService) Create(payload map[string]interface{}) (Jwt, error) {
	payload["iat"] = time.Now().Unix()
	payload["exp"] = time.Now().AddDate(1, 0, 0).Unix()

	token, err := service.jwtService.Create(payload)

	return token, err
}

func (service *RefreshTokenService) Validate(token Jwt) (map[string]interface{}, error) {
	payload, err := token.Payload()
	if err != nil {
		return nil, err
	}

	err = token.Validate(string(service.jwtService.secret.GetSecret()))
	if err != nil {
		return nil, err
	}

	return payload, nil
}
