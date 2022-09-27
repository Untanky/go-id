package auth

import (
	jwt "github.com/Untanky/go-id/jwt"
)

type TokenService[Payload any] interface {
	Create(payload Payload) (jwt.Jwt, error)
	Validate(token jwt.Jwt) (Payload, error)
}
