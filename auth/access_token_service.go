package auth

import (
	"time"

	jwt "github.com/Untanky/go-id/jwt"
	secret "github.com/Untanky/go-id/secret"
)

type AccessTokenService struct {
	jwtService *jwt.JwtService[secret.KeyPair]
}

func (service *AccessTokenService) Init(jwtService *jwt.JwtService[secret.KeyPair]) {
	service.jwtService = jwtService
}

func (service *AccessTokenService) Create(payload *RefreshTokenPayload) (jwt.Jwt, error) {
	accessTokenDuration, _ := time.ParseDuration("60m")

	payloadMap := make(map[string]interface{})
	payloadMap["sid"] = payload.Sid
	payloadMap["sub"] = payload.Sub
	payloadMap["iat"] = time.Now().Unix()
	payloadMap["exp"] = time.Now().Add(accessTokenDuration).Unix()

	token, err := service.jwtService.Create(payloadMap)

	return token, err
}

func (service *AccessTokenService) Validate(token jwt.Jwt) (*RefreshTokenPayload, error) {
	payload, err := token.Payload()
	if err != nil {
		return nil, err
	}

	err = token.Validate(string(service.jwtService.Secret.GetSecret().PublicKey))
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
