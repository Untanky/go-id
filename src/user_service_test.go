package goid_test

import (
	"testing"

	. "github.com/Untanky/go-id/src"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type UserServiceTestSuite struct {
	suite.Suite
	userRepo   UserRepository
	knownUsers []*User
	service    *UserService
}

func (suite *UserServiceTestSuite) SetupTest() {
	suite.userRepo = new(MemoryUserRepository)

	suite.service = new(UserService)
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

func (suite *UserServiceTestSuite) TestInactivate_SetStatusToDeactivated() {
	user0 := suite.knownUsers[0]

	err := suite.service.Inactivate(user0.Identifier)

	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), user0.Status, Inactive)
}

func (suite *UserServiceTestSuite) TestInactivate_ErrWhenAlreadyDeactivated() {
	user0 := suite.knownUsers[0]

	err := suite.service.Inactivate(user0.Identifier)

	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), user0.Status, Inactive)

	err = suite.service.Inactivate(user0.Identifier)
	assert.ErrorContains(suite.T(), err, "user is already inactive")
}

func (suite *UserServiceTestSuite) TestInactivate_ErrorWhenUserNotfound() {
	err := suite.service.Inactivate(unknownUserId)

	assert.ErrorContains(suite.T(), err, "no user found")
}

func (suite *UserServiceTestSuite) TestActivate_SetStatusToActiveWhenStatusIsDeactivated() {
	user0 := suite.knownUsers[0]
	err := suite.service.Inactivate(user0.Identifier)

	err = suite.service.Activate(user0.Identifier)

	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), user0.Status, Active)
}

func (suite *UserServiceTestSuite) TestActivate_ErrorWhenStatusIsAlreadyActive() {
	user0 := suite.knownUsers[0]
	err := suite.service.Activate(user0.Identifier)

	assert.ErrorContains(suite.T(), err, "user is already active")
}

func (suite *UserServiceTestSuite) TestActivate_ErrorWhenUserNotFound() {
	err := suite.service.Activate(unknownUserId)

	assert.ErrorContains(suite.T(), err, "no user found")
}

func (suite *UserServiceTestSuite) TestDelete_RemoveUserFromKnownUsers() {
	user0 := suite.knownUsers[0]

	err := suite.service.Delete(user0.Identifier)

	assert.Nil(suite.T(), err)

	foundUser, err := suite.userRepo.FindByIdentifier(user0.Identifier)
	assert.Error(suite.T(), err, "no user found")
	assert.Nil(suite.T(), foundUser)
}

func (suite *UserServiceTestSuite) TestDelete_ErrorWhenUserNotFound() {
	err := suite.service.Delete(unknownUserId)

	assert.ErrorContains(suite.T(), err, "no user found")
}

func TestUserService(t *testing.T) {
	suite.Run(t, new(UserServiceTestSuite))
}
