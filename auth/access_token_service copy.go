package auth

import (
	goid "github.com/Untanky/go-id/src"
)

type AccessTokenService struct {
	jwtService *JwtService[goid.KeyPair]
}

func (service *AccessTokenService) Init(jwtService *JwtService[goid.KeyPair]) {
	service.jwtService = jwtService
}
