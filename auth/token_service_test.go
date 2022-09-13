package auth_test

import (
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
}

func (suite *TokenTestSuite) SetupTest() {
}

func (suite *TokenTestSuite) Test_DoNothing() {
	service := new(TokenService)
	sub := "123"
	sid := "abc"

	tokenString, err := service.CreateRefreshToken(sub, sid)
	assert.Nil(suite.T(), err)

	splitToken := strings.SplitN(tokenString, ".", 3)
	payload := map[string]interface{}{}
	err = json.Unmarshal([]byte(splitToken[1]), &payload)

	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), sid, payload["sid"])
	assert.Equal(suite.T(), sub, payload["sub"])
	assert.Equal(suite.T(), float64(time.Now().Unix()), payload["iat"])
	assert.Equal(suite.T(), float64(time.Now().AddDate(1, 0, 0).Unix()), payload["exp"])
}

func TestTokenService(t *testing.T) {
	suite.Run(t, new(TokenTestSuite))
}
