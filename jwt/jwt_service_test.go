package auth_test

import (
	"testing"

	. "github.com/Untanky/go-id/jwt"
	goid "github.com/Untanky/go-id/src"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type JwtServiceTestSuite struct {
	suite.Suite
}

func (suite *JwtServiceTestSuite) SetupTest() {
}

func (suite *JwtServiceTestSuite) TestJwtCreate_CreateHS256Token() {
	key := goid.NewSecretValue("secret")
	jwtService := new(JwtService[goid.SecretString])
	jwtService.Init(HS256, key)
	data := map[string]interface{}{
		"foo":   "bar",
		"hello": "world",
	}

	token, err := jwtService.Create(data)
	header, headerErr := token.Header()
	payload, payloadErr := token.Payload()

	assert.Nil(suite.T(), headerErr)
	assert.Equal(suite.T(), "HS256", header.Alg)
	assert.Nil(suite.T(), payloadErr)
	assert.Equal(suite.T(), data, map[string]interface{}(payload))
	assert.Nil(suite.T(), token.Validate(string(key.GetSecret())))
	assert.Nil(suite.T(), err)
}

func (suite *JwtServiceTestSuite) TestJwtCreate_CreateRS256Token() {
	keyPair := goid.NewSecretPair(goid.KeyPair{
		PrivateKey: rsaPrivateKey,
		PublicKey:  rsaPublicKey,
	})

	jwtService := new(JwtService[goid.KeyPair])
	jwtService.Init(RS256, keyPair)
	data := map[string]interface{}{
		"foo":   "bar",
		"hello": "world",
	}

	token, err := jwtService.Create(data)
	header, headerErr := token.Header()
	payload, payloadErr := token.Payload()

	assert.Nil(suite.T(), headerErr)
	assert.Equal(suite.T(), "RS256", header.Alg)
	assert.Nil(suite.T(), payloadErr)
	assert.Equal(suite.T(), data, map[string]interface{}(payload))
	assert.Nil(suite.T(), token.Validate(string(keyPair.GetSecret().PublicKey)))
	assert.Nil(suite.T(), err)
}

func TestJwtService(t *testing.T) {
	suite.Run(t, new(JwtServiceTestSuite))
}
