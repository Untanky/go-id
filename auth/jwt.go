package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

func readBase64Json(base64Json string) (map[string]interface{}, error) {
	utf8Json, err := base64.RawStdEncoding.DecodeString(base64Json)
	if err != nil {
		return map[string]interface{}{}, errors.New("cannot convert from base64")
	}

	var object map[string]interface{}
	err = json.Unmarshal(utf8Json, &object)
	if err != nil {
		return map[string]interface{}{}, errors.New("cannot unmarschal json")
	}

	return object, nil
}

type Jwt string

type header struct {
	Alg string
	Typ string
}

type payload map[string]interface{}

func (jwt *Jwt) Header() (header, error) {
	splitJwt := strings.SplitN(string(*jwt), ".", 3)
	headerMap, err := readBase64Json(splitJwt[0])
	if err != nil {
		return header{}, err
	}

	alg, algOk := headerMap["alg"].(string)
	typ, typOk := headerMap["typ"].(string)
	if !algOk || !typOk {
		return header{}, errors.New("invalid header")
	}

	return header{
		Alg: alg,
		Typ: typ,
	}, nil
}

func (jwt *Jwt) Payload() (payload, error) {
	splitJwt := strings.SplitN(string(*jwt), ".", 3)
	payloadMap, err := readBase64Json(splitJwt[1])
	if err != nil {
		return payload{}, err
	}

	return payload(payloadMap), nil
}

func (token *Jwt) Validate(key string) error {
	_, err := jwt.Parse(string(*token), func(t *jwt.Token) (interface{}, error) {
		return []byte(key), nil
	})

	return err
}

func CreateJwt() Jwt {
	return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M"
}
