package main

import (
	"encoding/base64"
	"github.com/Untanky/go-id/user"
	"net/http"
	"strings"
	"time"

	"github.com/Untanky/go-id/auth"
	"github.com/gin-gonic/gin"
)

const AuthorizationHeader = "Authorization"

type AuthController struct {
	authService           *auth.LoginService
	refreshTokenService   auth.TokenService[*auth.RefreshTokenPayload]
	challengeTokenService auth.TokenService[*auth.ChallengeTokenPayload]
}

func (controller *AuthController) Init(
	authService *auth.LoginService,
	refreshTokenService auth.TokenService[*auth.RefreshTokenPayload],
	challengeTokenService auth.TokenService[*auth.ChallengeTokenPayload],
) {
	controller.authService = authService
	controller.refreshTokenService = refreshTokenService
	controller.challengeTokenService = challengeTokenService
}

func (controller *AuthController) Login(c *gin.Context) {
	userId, password, shouldReturn := controller.decodeBasicAuthHeader(c)
	if shouldReturn {
		return
	}

	loggedInUser, err := controller.authService.Login(userId, password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "unauthorized",
		})
		return
	}

	payload := auth.RefreshTokenPayload{
		Sid: "123",
		Sub: loggedInUser.Identifier,
	}
	token, err := controller.refreshTokenService.Create(&payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "token could not be created",
		})
		return
	}

	c.JSON(200, gin.H{
		"refreshToken": token,
	})
}

func (controller *AuthController) Register(c *gin.Context) {
	userId, password, shouldReturn := controller.decodeBasicAuthHeader(c)
	if shouldReturn {
		return
	}

	newUser := new(user.User)
	newUser.Identifier = userId
	newUser.Passkey = password
	newUser.Status = user.Inactive

	err := controller.authService.Register(newUser)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "userId already exists",
		})
		return
	}

	duration, _ := time.ParseDuration("72h")

	payload := &auth.ChallengeTokenPayload{
		Sub:      userId,
		Duration: duration,
		Event:    6,
	}
	_, err = controller.challengeTokenService.Create(payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "token could not be created",
		})
		return
	}

	c.JSON(http.StatusCreated, nil)
}

func (*AuthController) decodeBasicAuthHeader(c *gin.Context) (string, string, bool) {
	basic := c.Request.Header.Get(AuthorizationHeader)

	if basic == "" {
		c.JSON(400, gin.H{
			"message": "basic authorization required",
		})
		return "", "", true
	}

	tokenType, base64Token := basic[:6], basic[6:]

	if tokenType != "Basic " {
		c.JSON(400, gin.H{
			"message": "only basic authorization allowed",
		})
		return "", "", true
	}

	b, err := base64.StdEncoding.DecodeString(base64Token)
	if err != nil {
		c.JSON(400, gin.H{
			"message": "basic authorization must be base64 encoded",
		})
		return "", "", true
	}

	userIdPasswordPair := strings.SplitN(string(b), ":", 2)
	return userIdPasswordPair[0], userIdPasswordPair[1], false
}
