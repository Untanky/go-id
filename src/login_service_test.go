package goid_test

import (
	"testing"

	. "github.com/Untanky/go-id/src"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

const (
	knownUserId   = "knownUser"
	knownUserKey  = "Test1Test!"
	unknownUserId = "unknownUser"
	encrypted     = "abcdfa"
)

type MockEncrypter struct {
	mock.Mock
}

func (m *MockEncrypter) Encrypt(passkey []byte, salt []byte) []byte {
	args := m.Called(passkey, salt)
	return []byte(args.String(0))
}

type LoginTestSuite struct {
	suite.Suite
	userRepo   UserRepository
	encrypter  *MockEncrypter
	knownUsers []*User
	service    *LoginService
}

func (suite *LoginTestSuite) SetupTest() {
	suite.userRepo = new(MemoryUserRepository)
	suite.encrypter = new(MockEncrypter)

	suite.service = new(LoginService)
	suite.service.Init(suite.userRepo, suite.encrypter)

	suite.knownUsers = []*User{
		{Identifier: knownUserId + "0", Passkey: knownUserKey + "0", Status: Active},
		{Identifier: knownUserId + "1", Passkey: knownUserKey + "1", Status: Active},
		{Identifier: knownUserId + "2", Passkey: knownUserKey + "2", Status: Inactive},
	}

	for _, user := range suite.knownUsers {
		suite.encrypter.On("Encrypt", []byte(user.Passkey), []byte("salt")).Return(encrypted)
		copy := &User{
			Identifier: user.Identifier,
			Passkey:    user.Passkey,
			Status:     user.Status,
		}
		suite.service.Register(copy)
	}
}

func (suite *LoginTestSuite) TestLogin_LoginWithKnownUser() {
	user0 := suite.knownUsers[0]
	user1 := suite.knownUsers[1]

	expected0 := &User{
		Identifier: user0.Identifier,
		Passkey:    encrypted,
		Status:     user0.Status,
	}

	expected1 := &User{
		Identifier: user1.Identifier,
		Passkey:    encrypted,
		Status:     user1.Status,
	}

	loggedIn0, err := suite.service.Login(user0.Identifier, encrypted)
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), expected0, loggedIn0)

	loggedIn1, err := suite.service.Login(user1.Identifier, encrypted)
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), expected1, loggedIn1)
}

func (suite *LoginTestSuite) TestLogin_ErrorWithInactiveUser() {
	inactiveUser := suite.knownUsers[2]

	user, err := suite.service.Login(inactiveUser.Identifier, encrypted)
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
	encrypter  *MockEncrypter
	service    *LoginService
	knownUsers []*User
}

func (suite *RegisterTestSuite) SetupTest() {
	suite.userRepo = new(MemoryUserRepository)
	suite.encrypter = new(MockEncrypter)

	suite.service = new(LoginService)
	suite.service.Init(suite.userRepo, suite.encrypter)

	suite.knownUsers = []*User{}
}

func (suite *RegisterTestSuite) TestRegister_KnownUserShouldContainNewUser() {
	var err error
	user0 := &User{knownUserId + "0", knownUserKey + "0", Active}
	encrypted0 := "abc"
	user1 := &User{knownUserId + "1", knownUserKey + "1", Active}
	encrypted1 := "def"

	suite.encrypter.On("Encrypt", []byte(user0.Passkey), []byte("salt")).Return(encrypted0)
	suite.encrypter.On("Encrypt", []byte(user1.Passkey), []byte("salt")).Return(encrypted1)

	err = suite.service.Register(user0)
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), encrypted0, user0.Passkey)
	err = suite.service.Register(user1)
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), encrypted1, user1.Passkey)

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
	encrypted0 := "abc"
	user1 := &User{knownUserId, knownUserKey, Active}

	suite.encrypter.On("Encrypt", []byte(user0.Passkey), []byte("salt")).Return(encrypted0)

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
