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
	userRepo   UserRepository
	knownUsers []*User
	service    *LoginService
}

func (suite *LoginTestSuite) SetupTest() {
	suite.userRepo = new(MemoryUserRepository)

	suite.service = new(LoginService)
	suite.service.Init(suite.userRepo)

	suite.knownUsers = []*User{
		{Identifier: knownUserId + "0", Passkey: knownUserKey + "0", Status: Active},
		{Identifier: knownUserId + "1", Passkey: knownUserKey + "1", Status: Active},
		{Identifier: knownUserId + "2", Passkey: knownUserKey + "2", Status: Inactive},
	}

	for _, user := range suite.knownUsers {
		suite.userRepo.Create(user)
	}
}

func (suite *LoginTestSuite) TestLogin_LoginWithKnownUser() {
	user0 := suite.knownUsers[0]
	user1 := suite.knownUsers[1]

	loggedIn0, err := suite.service.Login(user0.Identifier, user0.Passkey)
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), user0, loggedIn0)

	loggedIn1, err := suite.service.Login(user1.Identifier, user1.Passkey)
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), user1, loggedIn1)
}

func (suite *LoginTestSuite) TestLogin_ErrorWithInactiveUser() {
	inactiveUser := suite.knownUsers[2]

	user, err := suite.service.Login(inactiveUser.Identifier, inactiveUser.Passkey)
	assert.ErrorContains(suite.T(), err, "user is inactive")
	assert.Nil(suite.T(), user)
}

func (suite *LoginTestSuite) TestLogin_ErrorWithKnownUserAndIncorrectPasskey() {
	user0 := suite.knownUsers[0]
	user1 := suite.knownUsers[1]

	user, err := suite.service.Login(user0.Identifier, user1.Passkey)
	assert.ErrorContains(suite.T(), err, "unauthorized")
	assert.Nil(suite.T(), user)

	user, err = suite.service.Login(user1.Identifier, user0.Passkey)
	assert.ErrorContains(suite.T(), err, "unauthorized")
	assert.Nil(suite.T(), user)

	user, err = suite.service.Login(user1.Identifier, "foo")
	assert.ErrorContains(suite.T(), err, "unauthorized")
	assert.Nil(suite.T(), user)
}

func (suite *LoginTestSuite) TestLogin_ErrorWithUnknownUser() {
	user, err := suite.service.Login(unknownUserId, "xyz")

	assert.ErrorContains(suite.T(), err, "unauthorized")
	assert.Nil(suite.T(), user)
}

type RegisterTestSuite struct {
	suite.Suite
	userRepo   UserRepository
	service    *LoginService
	knownUsers []*User
}

func (suite *RegisterTestSuite) SetupTest() {
	suite.userRepo = new(MemoryUserRepository)

	suite.service = new(LoginService)
	suite.service.Init(suite.userRepo)

	suite.knownUsers = []*User{}
}

func (suite *RegisterTestSuite) TestRegister_KnownUserShouldContainNewUser() {
	var err error
	user0 := &User{knownUserId + "0", knownUserKey, Active}
	user1 := &User{knownUserId + "1", knownUserKey, Active}

	err = suite.service.Register(user0)
	assert.Nil(suite.T(), err)
	err = suite.service.Register(user1)
	assert.Nil(suite.T(), err)

	foundUser, err := suite.userRepo.FindByIdentifier(user0.Identifier)
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), foundUser, user0)

	foundUser, err = suite.userRepo.FindByIdentifier(user1.Identifier)
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), foundUser, user1)
}

func (suite *RegisterTestSuite) TestRegister_ErrorWhenUserIdExists() {
	var err error
	user0 := &User{knownUserId, knownUserKey, Active}
	user1 := &User{knownUserId, knownUserKey, Active}

	err = suite.service.Register(user0)
	assert.Nil(suite.T(), err)
	err = suite.service.Register(user1)
	assert.ErrorContains(suite.T(), err, "Identifier already exists")

	foundUser, err := suite.userRepo.FindByIdentifier(user0.Identifier)
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), foundUser, user0)
}

func (suite *RegisterTestSuite) TestRegister_PasskeyContainsLetterNumberAndSpecialChar() {
	passKeyShorterThan10 := &User{knownUserId, "123456789", Active}
	passKeyWithoutNumber := &User{knownUserId, "abcdefghij", Active}
	passKeyWithoutUppercaseLetter := &User{knownUserId, "abcdefghi1", Active}
	passKeyWithoutLowercaseLetter := &User{knownUserId, "ABCDEFGHI1", Active}
	passKeyWithoutSpecialChar := &User{knownUserId, "aBcDeFgHi1", Active}

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

	assert.Len(suite.T(), suite.knownUsers, 0)
}

func TestLoginService(t *testing.T) {
	suite.Run(t, new(LoginTestSuite))
	suite.Run(t, new(RegisterTestSuite))
}
