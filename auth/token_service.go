package auth

type TokenService[Payload any] interface {
	Create(payload Payload) (Jwt, error)
	Validate(token Jwt) (Payload, error)
}
