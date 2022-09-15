package auth

type Jwt string

type header struct {
	Alg string
	Typ string
}

type payload map[string]interface{}

func (jwt *Jwt) Header() header {
	return header{
		Typ: "JWT",
		Alg: "HS256",
	}
}

func (jwt *Jwt) Payload() payload {
	return make(payload)
}

func (jwt *Jwt) Validate(key string) error {
	return nil
}

func CreateJwt() Jwt {
	return ".."
}
