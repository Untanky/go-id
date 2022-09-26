package auth

import (
	"time"

	goid "github.com/Untanky/go-id/src"
)

type AccessTokenService struct {
	jwtService *JwtService[goid.KeyPair]
}

func (service *AccessTokenService) Init(jwtService *JwtService[goid.KeyPair]) {
	service.jwtService = jwtService
}

func (service *AccessTokenService) Create(payload *RefreshTokenPayload) (Jwt, error) {
	payloadMap := make(map[string]interface{})
	payloadMap["sid"] = payload.Sid
	payloadMap["sub"] = payload.Sub
	payloadMap["iat"] = time.Now().Unix()
	payloadMap["exp"] = time.Now().AddDate(1, 0, 0).Unix()

	token, err := service.jwtService.Create(payloadMap)

	return token, err
}

func (service *AccessTokenService) Validate(token Jwt) (*RefreshTokenPayload, error) {
	payload, err := token.Payload()
	if err != nil {
		return nil, err
	}

	err = token.Validate(string(service.jwtService.secret.GetSecret().PublicKey))
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
