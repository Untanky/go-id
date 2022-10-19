package main_test

import (
	"github.com/Untanky/go-id/auth"
	"github.com/Untanky/go-id/jwt"
	"github.com/Untanky/go-id/secret"
	"github.com/Untanky/go-id/totp"
	"github.com/Untanky/go-id/user"
	"github.com/gin-gonic/gin"
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
	user                  *user.User
	otpService            *totp.OtpService
	controller            *ChallengeController
}

func (suite *ChallengeControllerSuite) SetupTest() {
	s := secret.NewSecretValue("secret")

	jwtService := new(jwt.JwtService[secret.SecretString])
	jwtService.Init(jwt.HS256, s)
	challengeTokenService := new(auth.ChallengeTokenService)
	challengeTokenService.Init(jwtService)
	suite.challengeTokenService = challengeTokenService

	otpService := new(totp.OtpService)
	otpService.Init(30)
	suite.otpService = otpService

	suite.user = &user.User{
		Identifier: "abc",
		Status:     user.Inactive,
	}

	userRepo := new(user.MemoryUserRepository)
	userRepo.Create(suite.user)

	userService := new(user.UserService)
	userService.Init(userRepo)

	controller := new(ChallengeController)
	controller.Init(challengeTokenService, userRepo, userService, otpService)
	suite.controller = controller
}

func (suite ChallengeControllerSuite) TestVerifyEmail_DoNothing() {
	w, context := buildContext()

	event := int64(5)
	duration, _ := time.ParseDuration("30m")
	payload := &auth.ChallengeTokenPayload{
		Sub:      "abc",
		Event:    event,
		Duration: duration,
	}

	challenge := totp.Challenge{
		ChallengeType: totp.EMAIL_CHALLENGE,
		Event:         event,
		Secret:        secret.NewSecretValue("secret"),
	}
	password := suite.otpService.GenerateOtp(challenge)

	context.BindJSON(gin.H{"password": password})
	w.Flush()

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
