package auth

type JwtService struct {
	method signingMethod
	secret string
}

func (service *JwtService) Init(method signingMethod, secret string) {
	service.method = method
	service.secret = secret
}

func (service *JwtService) Create(data map[string]interface{}) (Jwt, error) {
	return CreateJwt(service.method, data, service.secret)
}
