package auth

import (
	"time"

	jwt "github.com/Untanky/go-id/jwt"
	secret "github.com/Untanky/go-id/secret"
)

type RefreshTokenPayload struct {
	Sid string
	Sub string
	Iat int64
	Exp int64
}

type RefreshTokenService struct {
	jwtService *jwt.JwtService[secret.SecretString]
}

func (service *RefreshTokenService) Init(jwtService *jwt.JwtService[secret.SecretString]) {
	service.jwtService = jwtService
}

func (service *RefreshTokenService) Create(payload *RefreshTokenPayload) (jwt.Jwt, error) {
	payloadMap := make(map[string]interface{})
	payloadMap["sid"] = payload.Sid
	payloadMap["sub"] = payload.Sub
	payloadMap["iat"] = time.Now().Unix()
	payloadMap["exp"] = time.Now().AddDate(1, 0, 0).Unix()

	token, err := service.jwtService.Create(payloadMap)

	return token, err
}

func (service *RefreshTokenService) Validate(token jwt.Jwt) (*RefreshTokenPayload, error) {
	payload, err := token.Payload()
	if err != nil {
		return nil, err
	}

	err = token.Validate(string(service.jwtService.Secret.GetSecret()))
	if err != nil {
		return nil, err
	}

	iat := int64(payload["iat"].(float64))
	exp := int64(payload["exp"].(float64))

	return &RefreshTokenPayload{
		Sid: payload["sid"].(string),
		Sub: payload["sub"].(string),
		Iat: iat,
		Exp: exp,
	}, nil
}
