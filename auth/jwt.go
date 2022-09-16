package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

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

func readBase64Json(base64Json string) (map[string]interface{}, error) {
	utf8Json, err := base64.StdEncoding.DecodeString(base64Json)
	if err != nil {
		return map[string]interface{}{}, errors.New("cannot convert from base64")
	}

	var object map[string]interface{}
	err = json.Unmarshal(utf8Json, &object)
	fmt.Println(object)
	if err != nil {
		return map[string]interface{}{}, errors.New("cannot unmarschal json")
	}

	return object, nil
}

func (jwt *Jwt) Payload() payload {
	return make(payload)
}

func (jwt *Jwt) Validate(key string) error {
	return nil
}

func CreateJwt() Jwt {
	return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.."
}
