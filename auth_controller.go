package main

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/Untanky/go-id/auth"
	"github.com/gin-gonic/gin"
)

const AuthorizationHeader = "Authorization"

type AuthController struct {
	authService  *auth.LoginService
	tokenService auth.TokenService[*auth.RefreshTokenPayload]
}

func (controller *AuthController) Init(authService *auth.LoginService, tokenService auth.TokenService[*auth.RefreshTokenPayload]) {
	controller.authService = authService
	controller.tokenService = tokenService
}

func (controller *AuthController) Login(c *gin.Context) {
	userId, password, shouldReturn := controller.decodeBasicAuthHeader(c)
	if shouldReturn {
		return
	}

	user, err := controller.authService.Login(userId, password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "unauthorized",
		})
		return
	}

	payload := auth.RefreshTokenPayload{
		Sid: "123",
		Sub: user.Identifier,
	}
	token, err := controller.tokenService.Create(&payload)
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

func (*AuthController) decodeBasicAuthHeader(c *gin.Context) (string, string, bool) {
	basic := c.Request.Header.Get(AuthorizationHeader)

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
