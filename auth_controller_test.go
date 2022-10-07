package main_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/Untanky/go-id"
	"github.com/Untanky/go-id/auth"
	"github.com/Untanky/go-id/jwt"
	"github.com/Untanky/go-id/secret"
	"github.com/Untanky/go-id/user"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type AuthControllerSuite struct {
	suite.Suite

	controller AuthController
}

func (suite *AuthControllerSuite) SetupTest() {
	gin.SetMode(gin.TestMode)
	authService := new(auth.LoginService)
	authService.Init(new(user.MemoryUserRepository), auth.NewArgon2Encrypter())

	jwtService := new(jwt.JwtService[secret.SecretString])
	jwtService.Init(jwt.HS256, secret.NewSecretValue("secret"))
	tokenService := new(auth.RefreshTokenService)
	tokenService.Init(jwtService)

	controller := new(AuthController)
	controller.Init(authService, tokenService)

	assert.NotNil(suite.T(), controller)
}

func (suite *AuthControllerSuite) buildContext() (*httptest.ResponseRecorder, *gin.Context) {
	w := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(w)
	context.Request = &http.Request{
		Header: make(http.Header),
	}
	return w, context
}

func (suite *AuthControllerSuite) TestLogin_SucceedWithBasicToken() {
	w, context := suite.buildContext()
	context.Request.Header.Add(AuthorizationHeader, "Basic dXNlcjp0ZXN0")

	suite.controller.Login(context)

	assert.Equal(suite.T(), 200, w.Result().StatusCode)
	body, _ := io.ReadAll(w.Result().Body)
	assert.Contains(suite.T(), string(body), "\"userId\":\"user\"")
	assert.Contains(suite.T(), string(body), "\"password\":\"test\"")
}

func (suite *AuthControllerSuite) TestLogin_FailWithBearerToken() {
	w, context := suite.buildContext()
	context.Request.Header.Add(AuthorizationHeader, "Bearer dXNlcjp0ZXN0")

	suite.controller.Login(context)

	assert.Equal(suite.T(), 400, w.Result().StatusCode)
	body, _ := io.ReadAll(w.Result().Body)
	assert.Contains(suite.T(), string(body), "only basic authorization allowed")
}

func (suite *AuthControllerSuite) TestLogin_FailWithBasicTokenNotBase64() {
	w, context := suite.buildContext()
	context.Request.Header.Add(AuthorizationHeader, "Basic dXlc!jp0ZXN0")

	suite.controller.Login(context)

	assert.Equal(suite.T(), 400, w.Result().StatusCode)
	body, _ := io.ReadAll(w.Result().Body)
	assert.Contains(suite.T(), string(body), "basic authorization must be base64 encoded")
}

func TestAuthController(t *testing.T) {
	suite.Run(t, new(AuthControllerSuite))
}
