package main

import (
	"fmt"
	"github.com/Untanky/go-id/auth"
	"github.com/Untanky/go-id/jwt"
	"github.com/gin-gonic/gin"
	"net/http"
)

const (
	ChallengeHeader = "Challenge"
)

type ChallengeController struct {
	tokenService auth.TokenService[*auth.ChallengeTokenPayload]
}

func (controller *ChallengeController) Init(tokenService auth.TokenService[*auth.ChallengeTokenPayload]) {
	controller.tokenService = tokenService
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

	fmt.Println(payload)

	context.AbortWithStatus(200)
}
