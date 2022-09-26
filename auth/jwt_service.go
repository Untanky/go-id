package auth

import (
	goid "github.com/Untanky/go-id/src"
)

type JwtService struct {
	method signingMethod
	secret goid.Secret[goid.SecretString]
}

func (service *JwtService) Init(method signingMethod, secret goid.Secret[goid.SecretString]) {
	service.method = method
	service.secret = secret
}

func (service *JwtService) Create(data map[string]interface{}) (Jwt, error) {
	return CreateJwt(service.method, data, string(service.secret.GetSecret()))
}
