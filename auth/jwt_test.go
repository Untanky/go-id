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
}

func (suite *JwtTestSuite) TestJwt_HeaderHasRs256Alg() {
	token := Jwt("ewogICJhbGciOiAiUlMyNTYiLAogICJ0eXAiOiAiSldUIgp9..")

	header, err := token.Header()
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), header)
	assert.Equal(suite.T(), "RS256", header.Alg)
}

func (suite *JwtTestSuite) TestJwt_ErrorWhenNonBase64Encoded() {
	invalidBase64Token := Jwt("ewogICJhbGciOiAiUlMyNTYiL%AogICJ0eXAiOiAiSldUIgp9..")

	header, err := invalidBase64Token.Header()
	assert.ErrorContains(suite.T(), err, "cannot convert from base64")
	assert.NotNil(suite.T(), header)
}

func (suite *JwtTestSuite) TestJwt_ErrorWhenInvalidJsonEncoded() {
	invalidJsonToken := Jwt("ewogICJhbGciOiAiUlMyNTYiLAogICJ0eXAiOiAiSldUCn0=..")

	header, err := invalidJsonToken.Header()
	assert.ErrorContains(suite.T(), err, "cannot unmarschal json")
	assert.NotNil(suite.T(), header)
}

func (suite *JwtTestSuite) TestJwt_ErrorWhenHeaderFieldMissing() {
	invalidJsonToken := Jwt("ewogICJhbGciOiAiUlMyNTYiLAogICJ0eXBlIjogIkpXVCIKfQ==..")

	header, err := invalidJsonToken.Header()
	assert.ErrorContains(suite.T(), err, "invalid header")
	assert.NotNil(suite.T(), header)
}

func (suite *JwtTestSuite) TestCreateJwt() {
	token := CreateJwt()

	header, err := token.Header()
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), "HS256", header.Alg)
	assert.Equal(suite.T(), "JWT", header.Typ)
	assert.Equal(suite.T(), make(map[string]interface{}), map[string]interface{}(token.Payload()))
	assert.Nil(suite.T(), token.Validate("key"))
}

func TestJwtService(t *testing.T) {
	suite.Run(t, new(JwtTestSuite))
}
