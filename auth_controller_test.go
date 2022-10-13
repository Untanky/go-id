package main_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
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

	knownUsers []*user.User
	controller *AuthController
}

func (suite *AuthControllerSuite) SetupTest() {
	gin.SetMode(gin.TestMode)

	suite.knownUsers = []*user.User{
		{Identifier: "user", Passkey: "Test1Test!", Status: user.Active},
	}

	authService := new(auth.LoginService)
	authService.Init(new(user.MemoryUserRepository), auth.NewArgon2Encrypter())

	for _, u := range suite.knownUsers {
		authService.Register(u)
	}

	jwtService := new(jwt.JwtService[secret.SecretString])
	jwtService.Init(jwt.HS256, secret.NewSecretValue("secret"))
	refreshTokenService := new(auth.RefreshTokenService)
	refreshTokenService.Init(jwtService)

	challengeTokenService := new(auth.ChallengeTokenService)
	challengeTokenService.Init(jwtService)

	controller := new(AuthController)
	controller.Init(authService, refreshTokenService, challengeTokenService)
	suite.controller = controller

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
	context.Request.Header.Add(AuthorizationHeader, "Basic dXNlcjpUZXN0MVRlc3Qh")

	suite.controller.Login(context)

	assert.Equal(suite.T(), 200, w.Result().StatusCode)
	body, _ := io.ReadAll(w.Result().Body)
	assert.Contains(suite.T(), string(body), "\"refreshToken\"")
	regex := regexp.MustCompile(`"refreshToken"[:]"(?P<Token>.*)"`)
	result := regex.FindStringSubmatch(string(body))
	token := jwt.Jwt(result[1])
	assert.Nil(suite.T(), token.Validate("secret"))
}

func (suite *AuthControllerSuite) TestLogin_FailWithoutAuthorizationHeader() {
	w, context := suite.buildContext()

	suite.controller.Login(context)

	assert.Equal(suite.T(), 400, w.Result().StatusCode)
	body, _ := io.ReadAll(w.Result().Body)
	assert.Contains(suite.T(), string(body), "basic authorization required")
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

func (suite *AuthControllerSuite) TestLogin_FailWhenCredentialsDoNotMatch() {
	w, context := suite.buildContext()
	context.Request.Header.Add(AuthorizationHeader, "Basic dXNlcjpmYWls")

	suite.controller.Login(context)

	assert.Equal(suite.T(), 401, w.Result().StatusCode)
	body, _ := io.ReadAll(w.Result().Body)
	assert.Contains(suite.T(), string(body), "unauthorized")
}

func (suite *AuthControllerSuite) TestRegister_SuccessfullyRegister() {
	w, context := suite.buildContext()
	context.Request.Header.Add(AuthorizationHeader, "Basic bHVrYXM6VGVzdDFUZXN0IQ==")

	suite.controller.Register(context)

	assert.Equal(suite.T(), 201, w.Result().StatusCode)
}

func (suite *AuthControllerSuite) TestRegister_FailWithoutAuthorizationHeader() {
	w, context := suite.buildContext()

	suite.controller.Register(context)

	assert.Equal(suite.T(), 400, w.Result().StatusCode)
	body, _ := io.ReadAll(w.Result().Body)
	assert.Contains(suite.T(), string(body), "basic authorization required")
}

func (suite *AuthControllerSuite) TestRegister_FailWithBearerToken() {
	w, context := suite.buildContext()
	context.Request.Header.Add(AuthorizationHeader, "Bearer dXNlcjp0ZXN0")

	suite.controller.Register(context)

	assert.Equal(suite.T(), 400, w.Result().StatusCode)
	body, _ := io.ReadAll(w.Result().Body)
	assert.Contains(suite.T(), string(body), "only basic authorization allowed")
}

func (suite *AuthControllerSuite) TestRegister_FailWithBasicTokenNotBase64() {
	w, context := suite.buildContext()
	context.Request.Header.Add(AuthorizationHeader, "Basic dXlc!jp0ZXN0")

	suite.controller.Register(context)

	assert.Equal(suite.T(), 400, w.Result().StatusCode)
	body, _ := io.ReadAll(w.Result().Body)
	assert.Contains(suite.T(), string(body), "basic authorization must be base64 encoded")
}

func (suite *AuthControllerSuite) TestRegister_FailWhenUserIdAlreadyExists() {
	w, context := suite.buildContext()
	context.Request.Header.Add(AuthorizationHeader, "Basic dXNlcjpUZXN0MVRlc3Qh")

	suite.controller.Register(context)

	assert.Equal(suite.T(), 400, w.Result().StatusCode)
	body, _ := io.ReadAll(w.Result().Body)
	assert.Contains(suite.T(), string(body), "userId already exists")
}

func TestAuthController(t *testing.T) {
	suite.Run(t, new(AuthControllerSuite))
}
