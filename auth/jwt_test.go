package auth_test

import (
	"testing"

	. "github.com/Untanky/go-id/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type JwtTestSuite struct {
	suite.Suite
}

func (suite *JwtTestSuite) SetupTest() {
}

func (suite *JwtTestSuite) TestJwt_HeaderHasHs256Alg() {
	token := Jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..")

	header, err := token.Header()
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), header)
	assert.Equal(suite.T(), "HS256", header.Alg)
	assert.Equal(suite.T(), "JWT", header.Typ)
}

func (suite *JwtTestSuite) TestJwtHeader_HeaderHasRs256Alg() {
	token := Jwt("ewogICJhbGciOiAiUlMyNTYiLAogICJ0eXAiOiAiSldUIgp9..")

	header, err := token.Header()
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), header)
	assert.Equal(suite.T(), "JWT", header.Typ)
}

func (suite *JwtTestSuite) TestJwtHeader_ErrorWhenNonBase64Encoded() {
	invalidBase64Token := Jwt("ewogICJhbGciOiAiUlMyNTYiL%AogICJ0eXAiOiAiSldUIgp9..")

	header, err := invalidBase64Token.Header()
	assert.ErrorContains(suite.T(), err, "cannot convert from base64")
	assert.NotNil(suite.T(), header)
}

func (suite *JwtTestSuite) TestJwtHeader_ErrorWhenInvalidJsonEncoded() {
	invalidJsonToken := Jwt("ewogICJhbGciOiAiUlMyNTYiLAogICJ0eXAiOiAiSldUCn0..")

	header, err := invalidJsonToken.Header()
	assert.ErrorContains(suite.T(), err, "cannot unmarschal json")
	assert.NotNil(suite.T(), header)
}

func (suite *JwtTestSuite) TestJwtHeader_ErrorWhenHeaderFieldMissing() {
	invalidJsonToken := Jwt("ewogICJhbGciOiAiUlMyNTYiLAogICJ0eXBlIjogIkpXVCIKfQ..")

	header, err := invalidJsonToken.Header()
	assert.ErrorContains(suite.T(), err, "invalid header")
	assert.NotNil(suite.T(), header)
}

func (suite *JwtTestSuite) TestJwtPayload_PayloadHasHelloWorld() {
	token := Jwt(".ewogICJoZWxsbyI6ICJ3b3JsZCIKfQ.")

	payload, err := token.Payload()
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), payload)
	assert.Equal(suite.T(), "world", payload["hello"])
}

func (suite *JwtTestSuite) TestJwtPayload_ErrorWhenNonBase64Encoded() {
	invalidBase64Token := Jwt(".ewogICJoZWxsbyI6$ICJ3b3JsZCIKfQ.")

	header, err := invalidBase64Token.Payload()
	assert.ErrorContains(suite.T(), err, "cannot convert from base64")
	assert.NotNil(suite.T(), header)
}

func (suite *JwtTestSuite) TestJwtPayload_ErrorWhenInvalidJsonEncoded() {
	invalidJsonToken := Jwt(".ewogICJoZWxsbyI6ICJ3b3JsZAp9.")

	header, err := invalidJsonToken.Payload()
	assert.ErrorContains(suite.T(), err, "cannot unmarschal json")
	assert.NotNil(suite.T(), header)
}

func (suite *JwtTestSuite) TestJwtValidate_WithHS256Format() {
	key := "secret"
	hs256Token := Jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M")

	err := hs256Token.Validate(key)
	assert.Nil(suite.T(), err)
}

func (suite *JwtTestSuite) TestJwtValidate_WithRS256Format() {
	key := `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----`
	rs256Token := Jwt("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ")

	err := rs256Token.Validate(key)
	assert.Nil(suite.T(), err)
}

func (suite *JwtTestSuite) TestJwtValidate_WithES256Format() {
	key := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----`
	es256Token := Jwt("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA")

	err := es256Token.Validate(key)
	assert.Nil(suite.T(), err)
}

func (suite *JwtTestSuite) TestJwtValidate_WithPS256Format() {
	key := `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----`
	ps256Token := Jwt("eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.iOeNU4dAFFeBwNj6qdhdvm-IvDQrTa6R22lQVJVuWJxorJfeQww5Nwsra0PjaOYhAMj9jNMO5YLmud8U7iQ5gJK2zYyepeSuXhfSi8yjFZfRiSkelqSkU19I-Ja8aQBDbqXf2SAWA8mHF8VS3F08rgEaLCyv98fLLH4vSvsJGf6ueZSLKDVXz24rZRXGWtYYk_OYYTVgR1cg0BLCsuCvqZvHleImJKiWmtS0-CymMO4MMjCy_FIl6I56NqLE9C87tUVpo1mT-kbg5cHDD8I7MjCW5Iii5dethB4Vid3mZ6emKjVYgXrtkOQ-JyGMh6fnQxEFN1ft33GX2eRHluK9eg")

	err := ps256Token.Validate(key)
	assert.Nil(suite.T(), err)
}

func (suite *JwtTestSuite) TestJwtValidate_ErrorWhenUnknownSigningMethod() {
	key := "secret"
	unknownSigningToken := Jwt("ewogICJhbGciOiAiTEcyNTYiLAogICJ0eXAiOiAiSldUIgp9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M")

	err := unknownSigningToken.Validate(key)
	assert.ErrorContains(suite.T(), err, "signing method (alg) is unavailable")
}

func (suite *JwtTestSuite) TestCreateJwt() {
	token := CreateJwt()

	header, headerError := token.Header()
	payload, payloadError := token.Payload()
	assert.Nil(suite.T(), headerError)
	assert.Nil(suite.T(), payloadError)
	assert.Equal(suite.T(), "HS256", header.Alg)
	assert.Equal(suite.T(), "JWT", header.Typ)
	assert.Equal(suite.T(), make(map[string]interface{}), map[string]interface{}(payload))
	assert.Nil(suite.T(), token.Validate("secret"))
}

func TestJwtService(t *testing.T) {
	suite.Run(t, new(JwtTestSuite))
}
