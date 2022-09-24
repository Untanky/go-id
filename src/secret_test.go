package goid_test

import (
	"testing"

	. "github.com/Untanky/go-id/src"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type SecretTestSuite struct {
	suite.Suite
}

func (suite *SecretTestSuite) SetupTest() {
}

func (suite *SecretTestSuite) TestGetSecret() {
	value := []byte("secret_value")
	secret := NewSecretValue(value).(Secret)

	assert.NotNil(suite.T(), secret)
	assert.Equal(suite.T(), value, secret.GetSecret())
}

func (suite *SecretTestSuite) TestRotateSecret() {
	value := []byte("secret_value")
	nextValue := []byte("new_secret_value")
	secret := NewSecretValue(value)

	actual := secret.GetSecret()
	assert.NotNil(suite.T(), secret)
	assert.Equal(suite.T(), value, actual)

	secret.RotateSecret(nextValue)

	actual = secret.GetSecret()
	assert.NotEqual(suite.T(), value, actual)
	assert.Equal(suite.T(), nextValue, actual)
}

func TestTokenService(t *testing.T) {
	suite.Run(t, new(SecretTestSuite))
}
