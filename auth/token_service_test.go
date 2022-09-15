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

	validatedPayload, err := suite.service.ValidateRefreshToken(tokenString)

	assert.Equal(suite.T(), payload, validatedPayload)
	assert.Nil(suite.T(), err)
}

func (suite *TokenTestSuite) TestRefreshToken_ValidateJwtFailsBecauseOfWrongSecret() {
	fakeTokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwic2lkIjoiMDk4NzY1NDMyMSIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2Mjc4OTMxfQ.-Msx6dR3kerkZ8g0jyJgpZ1oki3Z-lWmbifP42m-eGg"

	payload, err := suite.service.ValidateRefreshToken(fakeTokenString)

	assert.Nil(suite.T(), payload)
	assert.ErrorContains(suite.T(), err, "signature")
}

func (suite *TokenTestSuite) TestRefreshToken_ValidateJwtFailsBecauseItExpired() {
	expiredTokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwic2lkIjoiMDk4NzY1NDMyMSIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2Mjc4OTMxfQ.UoWNJ5MjP4013Wll-m8WeLu2MR6pczHD2usf_A58Yww"

	payload, err := suite.service.ValidateRefreshToken(expiredTokenString)

	assert.Nil(suite.T(), payload)
	assert.ErrorContains(suite.T(), err, "expired")
}

func (suite *TokenTestSuite) TestRefreshToken_ValidateJwtFailsBecauseItWasIssuedInTheFuture() {
	futureTokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwic2lkIjoiMDk4NzY1NDMyMSIsImlhdCI6MTcxNzIzOTAyMiwiZXhwIjoxNzE2Mjc4OTMxfQ.eMy2GxxPi1MXxz46u_aJ24Bb4N-RDdHjqc_kPDwn8Nw"

	payload, err := suite.service.ValidateRefreshToken(futureTokenString)

	assert.Nil(suite.T(), payload)
	assert.ErrorContains(suite.T(), err, "before issued")
}

func TestTokenService(t *testing.T) {
	suite.Run(t, new(TokenTestSuite))
}
