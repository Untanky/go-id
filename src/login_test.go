package goid_test

import (
	"testing"

	. "github.com/Untanky/go-id/src"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

const (
	knownUserId   = "knownUser"
	knownUserKey  = "xyz"
	unknownUserId = "unknownUser"
)

type LoginTestSuite struct {
	suite.Suite
	VariableThatShouldStartAtFive int
}

func (suite *LoginTestSuite) SetupTest() {
	KnownUsers = []User{{Identifier: knownUserId + "0", Passkey: knownUserKey + "0"}, {Identifier: knownUserId + "1", Passkey: knownUserKey + "1"}}
}

func (suite *LoginTestSuite) TestLogin_LoginWithKnownUser() {
	var err error

	err = Login(KnownUsers[0].Identifier, KnownUsers[0].Passkey)
	assert.Nil(suite.T(), err)

	err = Login(KnownUsers[1].Identifier, KnownUsers[1].Passkey)
	assert.Nil(suite.T(), err)
}

func (suite *LoginTestSuite) TestLogin_LoginWithKnownUserAndIncorrectPasskey() {
	var err error

	err = Login(KnownUsers[0].Identifier, KnownUsers[1].Passkey)
	assert.ErrorContains(suite.T(), err, "unauthorized")

	err = Login(KnownUsers[1].Identifier, KnownUsers[0].Passkey)
	assert.ErrorContains(suite.T(), err, "unauthorized")

	err = Login(KnownUsers[1].Identifier, "foo")
	assert.ErrorContains(suite.T(), err, "unauthorized")
}

func (suite *LoginTestSuite) TestLogin_LoginWithUnknownUser() {
	err := Login(unknownUserId, "xyz")

	assert.ErrorContains(suite.T(), err, "unauthorized")
}

func TestExampleTestSuite(t *testing.T) {
	suite.Run(t, new(LoginTestSuite))
}
