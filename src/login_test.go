package goid_test

import (
	"testing"

	. "github.com/Untanky/go-id/src"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

const (
	knownUserId   = "knownUser"
	knownUserKey  = "Test1Test!"
	unknownUserId = "unknownUser"
)

type LoginTestSuite struct {
	suite.Suite
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

type RegisterTestSuite struct {
	suite.Suite
}

func (suite *RegisterTestSuite) SetupTest() {
	KnownUsers = []User{}
}

func (suite *RegisterTestSuite) TestRegister_KnownUserShouldContainNewUser() {
	var err error
	user1 := &User{knownUserId + "1", knownUserKey}
	user2 := &User{knownUserId + "2", knownUserKey}

	err = Register(user1)
	assert.Nil(suite.T(), err)
	err = Register(user2)
	assert.Nil(suite.T(), err)

	assert.Len(suite.T(), KnownUsers, 2)
	assert.Equal(suite.T(), KnownUsers[0], *user1)
	assert.Equal(suite.T(), KnownUsers[1], *user2)
}

func (suite *RegisterTestSuite) TestRegister_ErrorWhenUserIdExists() {
	var err error
	user1 := &User{knownUserId, knownUserKey}
	user2 := &User{knownUserId, knownUserKey}

	err = Register(user1)
	assert.Nil(suite.T(), err)
	err = Register(user2)
	assert.ErrorContains(suite.T(), err, "Identifier already exists")

	assert.Len(suite.T(), KnownUsers, 1)
	assert.Equal(suite.T(), KnownUsers[0], *user1)
}

func (suite *RegisterTestSuite) TestRegister_PasskeyContainsLetterNumberAndSpecialChar() {
	passKeyShorterThan10 := &User{knownUserId, "123456789"}
	passKeyWithoutNumber := &User{knownUserId, "abcdefghij"}
	passKeyWithoutUppercaseLetter := &User{knownUserId, "abcdefghi1"}
	passKeyWithoutLowercaseLetter := &User{knownUserId, "ABCDEFGHI1"}
	passKeyWithoutSpecialChar := &User{knownUserId, "aBcDeFgHi1"}

	errShorterThan10 := Register(passKeyShorterThan10)
	assert.ErrorContains(suite.T(), errShorterThan10, "Validation Error: Passkey too short")

	errWithoutNumber := Register(passKeyWithoutNumber)
	assert.ErrorContains(suite.T(), errWithoutNumber, "Validation Error: Passkey missing number")

	errWithoutUppercaseLetter := Register(passKeyWithoutUppercaseLetter)
	assert.ErrorContains(suite.T(), errWithoutUppercaseLetter, "Validation Error: Passkey missing uppercase character")

	errWithoutLowercaseLetter := Register(passKeyWithoutLowercaseLetter)
	assert.ErrorContains(suite.T(), errWithoutLowercaseLetter, "Validation Error: Passkey missing lowercase character")

	errWithoutSpecialChar := Register(passKeyWithoutSpecialChar)
	assert.ErrorContains(suite.T(), errWithoutSpecialChar, "Validation Error: Passkey missing special character")

	assert.Len(suite.T(), KnownUsers, 0)
}

func TestRegisterTestSuite(t *testing.T) {
	suite.Run(t, new(RegisterTestSuite))
}
