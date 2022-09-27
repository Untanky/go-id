package jwt

import (
	"errors"

	. "github.com/Untanky/go-id/secret"
)

type JwtService[Type SecretString | KeyPair] struct {
	method signingMethod
	Secret Secret[Type]
}

func (service *JwtService[Type]) Init(method signingMethod, secret Secret[Type]) {
	service.method = method
	service.Secret = secret
}

func (service *JwtService[Type]) Create(data map[string]interface{}) (Jwt, error) {
	if str, ok := any(service.Secret.GetSecret()).(SecretString); ok == true {
		return CreateJwt(service.method, data, string(str))
	}

	if pair, ok := any(service.Secret.GetSecret()).(KeyPair); ok == true {
		return CreateJwt(service.method, data, string(pair.PrivateKey))
	}

	return Jwt(""), errors.New("unknown secret type")
}
