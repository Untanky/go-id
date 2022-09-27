package auth

import (
	"errors"

	goid "github.com/Untanky/go-id/src"
)

type secret interface {
	goid.SecretString | goid.KeyPair
}

type JwtService[Type secret] struct {
	method signingMethod
	Secret goid.Secret[Type]
}

func (service *JwtService[Type]) Init(method signingMethod, secret goid.Secret[Type]) {
	service.method = method
	service.Secret = secret
}

func (service *JwtService[Type]) Create(data map[string]interface{}) (Jwt, error) {
	if str, ok := any(service.Secret.GetSecret()).(goid.SecretString); ok == true {
		return CreateJwt(service.method, data, string(str))
	}

	if pair, ok := any(service.Secret.GetSecret()).(goid.KeyPair); ok == true {
		return CreateJwt(service.method, data, string(pair.PrivateKey))
	}

	return Jwt(""), errors.New("unknown secret type")
}
