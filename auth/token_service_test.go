package auth_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	. "github.com/Untanky/go-id/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type TokenTestSuite struct {
	suite.Suite
	service *TokenService
}

func (suite *TokenTestSuite) SetupTest() {
	suite.service = new(TokenService)
	suite.service.Secret = []byte("key")
}

func (suite *TokenTestSuite) TestRefreshToken_CreateAndValidateJwt() {
	sub := "123"
	sid := "abc"

	tokenString, err := suite.service.CreateRefreshToken(sub, sid)
	assert.Nil(suite.T(), err)

	splitToken := strings.SplitN(tokenString, ".", 3)
	payloadString, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(splitToken[1])
	payload := map[string]interface{}{}
	err = json.Unmarshal(payloadString, &payload)

	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), sid, payload["sid"])
	assert.Equal(suite.T(), sub, payload["sub"])
	assert.Equal(suite.T(), float64(time.Now().Unix()), payload["iat"])
	assert.Equal(suite.T(), float64(time.Now().AddDate(1, 0, 0).Unix()), payload["exp"])

	payload, err = suite.service.ValidateRefreshToken(tokenString)

	assert.NotNil(suite.T(), payload)
	assert.Nil(suite.T(), err)
}

func (suite *TokenTestSuite) TestRefreshToken_ValidateJwtFailsBecauseOfWrongSecret() {
	fakeTokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwic2lkIjoiMDk4NzY1NDMyMSIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2Mjc4OTMxfQ.-Msx6dR3kerkZ8g0jyJgpZ1oki3Z-lWmbifP42m-eGg"

	payload, err := suite.service.ValidateRefreshToken(fakeTokenString)

	assert.Nil(suite.T(), payload)
	assert.ErrorContains(suite.T(), err, "signature is invalid")
}

func TestTokenService(t *testing.T) {
	suite.Run(t, new(TokenTestSuite))
}
