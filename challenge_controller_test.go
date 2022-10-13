package main_test

import (
	"github.com/Untanky/go-id/auth"
	"github.com/Untanky/go-id/jwt"
	"github.com/Untanky/go-id/secret"
	"github.com/stretchr/testify/assert"
	"io"
	"testing"
	"time"

	. "github.com/Untanky/go-id"
	"github.com/stretchr/testify/suite"
)

type ChallengeControllerSuite struct {
	suite.Suite

	challengeTokenService auth.TokenService[*auth.ChallengeTokenPayload]
	controller *ChallengeController
}

func (suite *ChallengeControllerSuite) SetupTest() {
	s := secret.NewSecretValue("secret")

	jwtService := new(jwt.JwtService[secret.SecretString])
	jwtService.Init(jwt.HS256, s)
	challengeTokenService := new(auth.ChallengeTokenService)
	challengeTokenService.Init(jwtService)
	suite.challengeTokenService = challengeTokenService

	controller := new(ChallengeController)
	controller.Init(challengeTokenService)
	suite.controller = controller
}

func (suite ChallengeControllerSuite) TestVerifyEmail_DoNothing() {
	w, context := buildContext()

	duration, _ := time.ParseDuration("30m")
	payload := &auth.ChallengeTokenPayload{
		Sub: "abc",
		Event: 5,
		Duration: duration,
	}

	token, _ := suite.challengeTokenService.Create(payload)

	context.Request.Header.Set(ChallengeHeader, string(token))
	suite.controller.VerifyEmail(context)

	assert.Equal(suite.T(), 200, w.Result().StatusCode)
}

func (suite ChallengeControllerSuite) TestVerifyEmail_MissingChallengeHeader() {
	w, context := buildContext()

	suite.controller.VerifyEmail(context)

	assert.Equal(suite.T(), 400, w.Result().StatusCode)
	body, _ := io.ReadAll(w.Result().Body)
	assert.Contains(suite.T(), string(body), `missing required header \"Challenge\"`)
}

func (suite ChallengeControllerSuite) TestVerifyEmail_InvalidChallengeToken() {
	w, context := buildContext()

	context.Request.Header.Set(ChallengeHeader, "foo..")
	suite.controller.VerifyEmail(context)

	assert.Equal(suite.T(), 401, w.Result().StatusCode)
	body, _ := io.ReadAll(w.Result().Body)
	assert.Contains(suite.T(), string(body), `cannot validate challenge token`)
}

func TestChallengeController(t *testing.T) {
	suite.Run(t, new(ChallengeControllerSuite))
}
