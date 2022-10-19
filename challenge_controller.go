package main

import (
	"fmt"
	"github.com/Untanky/go-id/auth"
	"github.com/Untanky/go-id/jwt"
	"github.com/Untanky/go-id/secret"
	"github.com/Untanky/go-id/totp"
	"github.com/Untanky/go-id/user"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
)

const (
	ChallengeHeader = "Challenge"
)

type ChallengeController struct {
	tokenService auth.TokenService[*auth.ChallengeTokenPayload]
	userRepo     user.UserRepository
	userService  *user.UserService
	otpService   *totp.OtpService
}

func (controller *ChallengeController) Init(
	tokenService auth.TokenService[*auth.ChallengeTokenPayload],
	userRepo user.UserRepository,
	userService *user.UserService,
	otpService *totp.OtpService,
) {
	controller.tokenService = tokenService
	controller.userRepo = userRepo
	controller.userService = userService
	controller.otpService = otpService
}

func (controller *ChallengeController) VerifyEmail(context *gin.Context) {
	challengeString := context.Request.Header.Get(ChallengeHeader)

	if challengeString == "" {
		context.JSON(400, gin.H{
			"message": fmt.Sprintf(`missing required header "%s"`, ChallengeHeader),
		})
		return
	}

	token := jwt.Jwt(string(challengeString))

	payload, err := controller.tokenService.Validate(token)

	if err != nil {
		context.JSON(http.StatusUnauthorized, gin.H{
			"message": "cannot validate challenge token",
		})
		return
	}

	password, err := io.ReadAll(context.Request.Body)

	if err != nil {
		context.JSON(http.StatusUnauthorized, gin.H{
			"message": "cannot read body",
		})
		return
	}

	challenge := totp.Challenge{
		ChallengeType: totp.EMAIL_CHALLENGE,
		Event:         payload.Event,
		Secret:        secret.NewSecretValue("secret"),
	}

	controller.otpService.ValidateOtp(string(password), challenge)

	context.AbortWithStatus(200)
}
