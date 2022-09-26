package auth_test

import (
	"testing"
	"time"

	. "github.com/Untanky/go-id/auth"
	. "github.com/Untanky/go-id/src"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type RefreshTokenTestSuite struct {
	suite.Suite
	service TokenService[*RefreshTokenPayload]
}

func (suite *RefreshTokenTestSuite) SetupTest() {
	secret := NewSecretValue("key")

	jwtService := new(JwtService[SecretString])
	jwtService.Init(HS256, secret)

	refreshToken := new(RefreshTokenService)
	refreshToken.Init(jwtService)
	suite.service = refreshToken
}

func (suite *RefreshTokenTestSuite) TestRefreshToken_CreateAndValidateJwt() {
	sub := "123"
	sid := "abc"
	payload := &RefreshTokenPayload{
		Sid: sid,
		Sub: sub,
	}

	tokenString, err := suite.service.Create(payload)
	assert.Nil(suite.T(), err)

	payloadMap, err := tokenString.Payload()

	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), sid, payloadMap["sid"])
	assert.Equal(suite.T(), sub, payloadMap["sub"])
	assert.Equal(suite.T(), float64(time.Now().Unix()), payloadMap["iat"])
	assert.Equal(suite.T(), float64(time.Now().AddDate(1, 0, 0).Unix()), payloadMap["exp"])

	validatedPayload, err := suite.service.Validate(tokenString)

	assert.Equal(suite.T(), payload.Sid, validatedPayload.Sid)
	assert.Equal(suite.T(), payload.Sub, validatedPayload.Sub)
	assert.Equal(suite.T(), float64(time.Now().Unix()), validatedPayload.Iat)
	assert.Equal(suite.T(), float64(time.Now().AddDate(1, 0, 0).Unix()), validatedPayload.Exp)
	assert.Nil(suite.T(), err)
}

func (suite *RefreshTokenTestSuite) TestRefreshToken_ValidateJwtFailsBecauseOfWrongSecret() {
	fakeTokenString := Jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwic2lkIjoiMDk4NzY1NDMyMSIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2Mjc4OTMxfQ.-Msx6dR3kerkZ8g0jyJgpZ1oki3Z-lWmbifP42m-eGg")

	payload, err := suite.service.Validate(fakeTokenString)

	assert.Nil(suite.T(), payload)
	assert.ErrorContains(suite.T(), err, "signature")
}

func (suite *RefreshTokenTestSuite) TestRefreshToken_ValidateJwtFailsBecauseItExpired() {
	expiredTokenString := Jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwic2lkIjoiMDk4NzY1NDMyMSIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2Mjc4OTMxfQ.UoWNJ5MjP4013Wll-m8WeLu2MR6pczHD2usf_A58Yww")

	payload, err := suite.service.Validate(expiredTokenString)

	assert.Nil(suite.T(), payload)
	assert.ErrorContains(suite.T(), err, "expired")
}

func (suite *RefreshTokenTestSuite) TestRefreshToken_ValidateJwtFailsBecauseItWasIssuedInTheFuture() {
	futureTokenString := Jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwic2lkIjoiMDk4NzY1NDMyMSIsImlhdCI6MTcxNzIzOTAyMiwiZXhwIjoxNzE2Mjc4OTMxfQ.eMy2GxxPi1MXxz46u_aJ24Bb4N-RDdHjqc_kPDwn8Nw")

	payload, err := suite.service.Validate(futureTokenString)

	assert.Nil(suite.T(), payload)
	assert.ErrorContains(suite.T(), err, "before issued")
}

type AccessTokenTestSuite struct {
	suite.Suite
	service *AccessTokenService
}

func (suite *AccessTokenTestSuite) SetupTest() {
	secret := NewSecretPair(KeyPair{
		PrivateKey: rsaPrivateKey,
		PublicKey:  rsaPublicKey,
	})

	jwtService := new(JwtService[KeyPair])
	jwtService.Init(RS256, secret)

	accessToken := new(AccessTokenService)
	accessToken.Init(jwtService)
	suite.service = accessToken
}

func (suite *AccessTokenTestSuite) TestAccessToken_DoNothing() {
	sub := "123"
	sid := "abc"
	payload := &RefreshTokenPayload{
		Sid: sid,
		Sub: sub,
	}

	token, err := suite.service.Create(payload)
	assert.Nil(suite.T(), err)

	payloadMap, err := token.Payload()
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), sid, payloadMap["sid"])
	assert.Equal(suite.T(), sub, payloadMap["sub"])
	assert.Equal(suite.T(), float64(time.Now().Unix()), payloadMap["iat"])
	assert.Equal(suite.T(), float64(time.Now().AddDate(1, 0, 0).Unix()), payloadMap["exp"])

	validatedPayload, err := suite.service.Validate(token)
	assert.Equal(suite.T(), payload.Sid, validatedPayload.Sid)
	assert.Equal(suite.T(), payload.Sub, validatedPayload.Sub)
	assert.Equal(suite.T(), float64(time.Now().Unix()), validatedPayload.Iat)
	assert.Equal(suite.T(), float64(time.Now().AddDate(1, 0, 0).Unix()), validatedPayload.Exp)
	assert.Nil(suite.T(), err)
}

func TestTokenService(t *testing.T) {
	suite.Run(t, new(RefreshTokenTestSuite))
}
