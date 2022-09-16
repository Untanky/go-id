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
	invalidJsonToken := Jwt("ewogICJhbGciOiAiUlMyNTYiLAogICJ0eXAiOiAiSldUCn0=..")

	header, err := invalidJsonToken.Header()
	assert.ErrorContains(suite.T(), err, "cannot unmarschal json")
	assert.NotNil(suite.T(), header)
}

func (suite *JwtTestSuite) TestJwtHeader_ErrorWhenHeaderFieldMissing() {
	invalidJsonToken := Jwt("ewogICJhbGciOiAiUlMyNTYiLAogICJ0eXBlIjogIkpXVCIKfQ==..")

	header, err := invalidJsonToken.Header()
	assert.ErrorContains(suite.T(), err, "invalid header")
	assert.NotNil(suite.T(), header)
}

func (suite *JwtTestSuite) TestJwtPayload_PayloadHasHelloWorld() {
	token := Jwt(".ewogICJoZWxsbyI6ICJ3b3JsZCIKfQ==.")

	payload, err := token.Payload()
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), payload)
	assert.Equal(suite.T(), "world", payload["hello"])
}

func (suite *JwtTestSuite) TestJwtPayload_ErrorWhenNonBase64Encoded() {
	invalidBase64Token := Jwt(".ewogICJoZWxsbyI6$ICJ3b3JsZCIKfQ==.")

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

func (suite *JwtTestSuite) TestCreateJwt() {
	token := CreateJwt()

	header, headerError := token.Header()
	payload, payloadError := token.Payload()
	assert.Nil(suite.T(), headerError)
	assert.Nil(suite.T(), payloadError)
	assert.Equal(suite.T(), "HS256", header.Alg)
	assert.Equal(suite.T(), "JWT", header.Typ)
	assert.Equal(suite.T(), make(map[string]interface{}), map[string]interface{}(payload))
	assert.Nil(suite.T(), token.Validate("key"))
}

func TestJwtService(t *testing.T) {
	suite.Run(t, new(JwtTestSuite))
}
