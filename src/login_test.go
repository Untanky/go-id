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
	service *LoginService
}

func (suite *LoginTestSuite) SetupTest() {
	suite.service = new(LoginService)
	suite.service.KnownUsers = []*User{{Identifier: knownUserId + "0", Passkey: knownUserKey + "0", Status: "active"}, {Identifier: knownUserId + "1", Passkey: knownUserKey + "1", Status: "active"}}
}

func (suite *LoginTestSuite) TestLogin_LoginWithKnownUser() {
	user0 := suite.service.KnownUsers[0]
	user1 := suite.service.KnownUsers[1]
	var err error

	err = suite.service.Login(user0.Identifier, user0.Passkey)
	assert.Nil(suite.T(), err)

	err = suite.service.Login(user1.Identifier, user1.Passkey)
	assert.Nil(suite.T(), err)
}

func (suite *LoginTestSuite) TestLogin_LoginWithKnownUserAndIncorrectPasskey() {
	user0 := suite.service.KnownUsers[0]
	user1 := suite.service.KnownUsers[1]
	var err error

	err = suite.service.Login(user0.Identifier, user1.Passkey)
	assert.ErrorContains(suite.T(), err, "unauthorized")

	err = suite.service.Login(user1.Identifier, user0.Passkey)
	assert.ErrorContains(suite.T(), err, "unauthorized")

	err = suite.service.Login(user1.Identifier, "foo")
	assert.ErrorContains(suite.T(), err, "unauthorized")
}

func (suite *LoginTestSuite) TestLogin_LoginWithUnknownUser() {
	err := suite.service.Login(unknownUserId, "xyz")

	assert.ErrorContains(suite.T(), err, "unauthorized")
}

func (suite *LoginTestSuite) TestDeactivate_SetStatusToDeactivatedAndCannotLogin() {
	user := suite.service.KnownUsers[0]

	err := suite.service.Deactive(user.Identifier)

	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), user.Status, "deactivated")

	err = suite.service.Login(user.Identifier, user.Passkey)
	assert.ErrorContains(suite.T(), err, "user is deactivated")
}

func (suite *LoginTestSuite) TestDeactivate_ErrorWhenUserNotfound() {
	err := suite.service.Deactive(unknownUserId)

	assert.ErrorContains(suite.T(), err, "No user found")
}

type RegisterTestSuite struct {
	suite.Suite
	service *LoginService
}

func (suite *RegisterTestSuite) SetupTest() {
	suite.service = new(LoginService)
	suite.service.KnownUsers = []*User{}
}

func (suite *RegisterTestSuite) TestRegister_KnownUserShouldContainNewUser() {
	var err error
	user0 := &User{knownUserId + "0", knownUserKey, "active"}
	user1 := &User{knownUserId + "1", knownUserKey, "active"}

	err = suite.service.Register(user0)
	assert.Nil(suite.T(), err)
	err = suite.service.Register(user1)
	assert.Nil(suite.T(), err)

	assert.Len(suite.T(), suite.service.KnownUsers, 2)
	assert.Equal(suite.T(), suite.service.KnownUsers[0], user0)
	assert.Equal(suite.T(), suite.service.KnownUsers[1], user1)
}

func (suite *RegisterTestSuite) TestRegister_ErrorWhenUserIdExists() {
	var err error
	user0 := &User{knownUserId, knownUserKey, "active"}
	user1 := &User{knownUserId, knownUserKey, "active"}

	err = suite.service.Register(user0)
	assert.Nil(suite.T(), err)
	err = suite.service.Register(user1)
	assert.ErrorContains(suite.T(), err, "Identifier already exists")

	assert.Len(suite.T(), suite.service.KnownUsers, 1)
	assert.Equal(suite.T(), suite.service.KnownUsers[0], user0)
}

func (suite *RegisterTestSuite) TestRegister_PasskeyContainsLetterNumberAndSpecialChar() {
	passKeyShorterThan10 := &User{knownUserId, "123456789", "active"}
	passKeyWithoutNumber := &User{knownUserId, "abcdefghij", "active"}
	passKeyWithoutUppercaseLetter := &User{knownUserId, "abcdefghi1", "active"}
	passKeyWithoutLowercaseLetter := &User{knownUserId, "ABCDEFGHI1", "active"}
	passKeyWithoutSpecialChar := &User{knownUserId, "aBcDeFgHi1", "active"}

	errShorterThan10 := suite.service.Register(passKeyShorterThan10)
	assert.ErrorContains(suite.T(), errShorterThan10, "Validation Error: Passkey too short")

	errWithoutNumber := suite.service.Register(passKeyWithoutNumber)
	assert.ErrorContains(suite.T(), errWithoutNumber, "Validation Error: Passkey missing number")

	errWithoutUppercaseLetter := suite.service.Register(passKeyWithoutUppercaseLetter)
	assert.ErrorContains(suite.T(), errWithoutUppercaseLetter, "Validation Error: Passkey missing uppercase character")

	errWithoutLowercaseLetter := suite.service.Register(passKeyWithoutLowercaseLetter)
	assert.ErrorContains(suite.T(), errWithoutLowercaseLetter, "Validation Error: Passkey missing lowercase character")

	errWithoutSpecialChar := suite.service.Register(passKeyWithoutSpecialChar)
	assert.ErrorContains(suite.T(), errWithoutSpecialChar, "Validation Error: Passkey missing special character")

	assert.Len(suite.T(), suite.service.KnownUsers, 0)
}

func TestLoginService(t *testing.T) {
	suite.Run(t, new(LoginTestSuite))
	suite.Run(t, new(RegisterTestSuite))
}
