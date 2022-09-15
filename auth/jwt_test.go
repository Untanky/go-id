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

func (suite *JwtTestSuite) TestCreateJwt() {
	token := CreateJwt()

	assert.Equal(suite.T(), "HS256", token.Header().Alg)
	assert.Equal(suite.T(), "JWT", token.Header().Typ)
	assert.Equal(suite.T(), make(map[string]interface{}), map[string]interface{}(token.Payload()))
	assert.Nil(suite.T(), token.Validate("key"))
}

func TestJwtService(t *testing.T) {
	suite.Run(t, new(JwtTestSuite))
}
