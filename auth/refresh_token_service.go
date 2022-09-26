package auth

import (
	"time"

	goid "github.com/Untanky/go-id/src"
)

type RefreshTokenPayload struct {
	Sid string
	Sub string
	Iat float64
	Exp float64
}

type RefreshTokenService struct {
	jwtService *JwtService[goid.SecretString]
}

func (service *RefreshTokenService) Init(jwtService *JwtService[goid.SecretString]) {
	service.jwtService = jwtService
}

func (service *RefreshTokenService) Create(payload *RefreshTokenPayload) (Jwt, error) {
	payloadMap := make(map[string]interface{})
	payloadMap["sid"] = payload.Sid
	payloadMap["sub"] = payload.Sub
	payloadMap["iat"] = time.Now().Unix()
	payloadMap["exp"] = time.Now().AddDate(1, 0, 0).Unix()

	token, err := service.jwtService.Create(payloadMap)

	return token, err
}

func (service *RefreshTokenService) Validate(token Jwt) (*RefreshTokenPayload, error) {
	payload, err := token.Payload()
	if err != nil {
		return nil, err
	}

	err = token.Validate(string(service.jwtService.secret.GetSecret()))
	if err != nil {
		return nil, err
	}

	return &RefreshTokenPayload{
		Sid: payload["sid"].(string),
		Sub: payload["sub"].(string),
		Iat: payload["iat"].(float64),
		Exp: payload["exp"].(float64),
	}, nil
}
