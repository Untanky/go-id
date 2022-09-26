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
	value := "secret_value"
	secret := NewSecretValue(value)

	assert.NotNil(suite.T(), secret)
	assert.Equal(suite.T(), value, string(secret.GetSecret()))
}

func TestTokenService(t *testing.T) {
	suite.Run(t, new(SecretTestSuite))
}

func (suite *SecretTestSuite) TestRotateSecret() {
	value := "secret_value"
	nextValue := "new_secret_value"
	secret := NewRotatingSecret(NewSecretValue(value))

	actual := secret.GetSecret()
	assert.NotNil(suite.T(), secret)
	assert.Equal(suite.T(), value, string(actual))

	secret.Rotate(NewSecretValue(nextValue))

	actual = secret.GetSecret()
	assert.NotEqual(suite.T(), value, actual)
	assert.Equal(suite.T(), nextValue, string(actual))
}
