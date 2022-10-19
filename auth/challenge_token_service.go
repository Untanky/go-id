package auth

import (
	"fmt"
	"time"

	jwt "github.com/Untanky/go-id/jwt"
	secret "github.com/Untanky/go-id/secret"
)

type ChallengeTokenPayload struct {
	Sub      string
	Iat      int64
	Exp      int64
	Duration time.Duration
	Event    int64
}

type ChallengeTokenService struct {
	jwtService *jwt.JwtService[secret.SecretString]
}

func (service *ChallengeTokenService) Init(jwtService *jwt.JwtService[secret.SecretString]) {
	service.jwtService = jwtService
}

func (service *ChallengeTokenService) Create(payload *ChallengeTokenPayload) (jwt.Jwt, error) {
	payloadMap := make(map[string]interface{})
	payloadMap["sub"] = payload.Sub
	payloadMap["iat"] = time.Now().Unix()
	payloadMap["exp"] = time.Now().Add(payload.Duration).Unix()
	payloadMap["event"] = payload.Event

	token, err := service.jwtService.Create(payloadMap)

	return token, err
}

func (service *ChallengeTokenService) Validate(token jwt.Jwt) (*ChallengeTokenPayload, error) {
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
	event := int64(payload["event"].(float64))
	duration, err := time.ParseDuration(fmt.Sprintf("%ds", exp-iat))

	if err != nil {
		return nil, err
	}

	return &ChallengeTokenPayload{
		Sub:      payload["sub"].(string),
		Iat:      iat,
		Exp:      exp,
		Duration: duration,
		Event:    event,
	}, nil
}
