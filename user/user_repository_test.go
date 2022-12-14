package user_test

import (
	"testing"

	. "github.com/Untanky/go-id/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type UserRepoTestSuite struct {
	suite.Suite
	user0 *User
	user1 *User
	repo  UserRepository
}

func (suite *UserRepoTestSuite) SetupTest() {
	suite.user0 = &User{
		Identifier: "abc",
		Passkey:    "abc",
		Status:     Active,
	}
	suite.user1 = &User{
		Identifier: "abc2",
		Passkey:    "abc",
		Status:     Active,
	}
	suite.repo = new(MemoryUserRepository)
}

func (suite *UserRepoTestSuite) TestCreate_CreateTwoThenFindTwo() {
	err := suite.repo.Create(suite.user0)
	assert.Nil(suite.T(), err)
	err = suite.repo.Create(suite.user1)
	assert.Nil(suite.T(), err)

	foundUser0, err := suite.repo.FindByIdentifier(suite.user0.Identifier)
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), suite.user0, foundUser0)
	foundUser1, err := suite.repo.FindByIdentifier(suite.user1.Identifier)
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), suite.user1, foundUser1)
}

func (suite *UserRepoTestSuite) TestCreate_ErrorWhenIdenfifierAlreadyExists() {
	err := suite.repo.Create(suite.user0)
	assert.Nil(suite.T(), err)
	err = suite.repo.Create(suite.user0)
	assert.ErrorContains(suite.T(), err, "already exists")
}

func (suite *UserRepoTestSuite) TestUpdate_UpdateUserWhenFound() {
	err := suite.repo.Create(suite.user0)
	assert.Nil(suite.T(), err)

	updatedUser := &User{
		Identifier: suite.user0.Identifier,
		Passkey:    "foo",
		Status:     Inactive,
	}

	err = suite.repo.Update(updatedUser)
	assert.Nil(suite.T(), err)

	foundUser0, err := suite.repo.FindByIdentifier(updatedUser.Identifier)
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), updatedUser, foundUser0)
}

func (suite *UserRepoTestSuite) TestUpdate_ErrorWhenUserNotFound() {
	updatedUser := &User{
		Identifier: suite.user0.Identifier,
		Passkey:    "foo",
		Status:     Inactive,
	}

	err := suite.repo.Update(updatedUser)

	assert.ErrorContains(suite.T(), err, "no user found")
}

func (suite *UserRepoTestSuite) TestRemove_ErrorWhenUserNotFound() {
	err := suite.repo.Remove(suite.user0.Identifier + "foo")

	assert.ErrorContains(suite.T(), err, "no user found")
}

func (suite *UserRepoTestSuite) TestRemove_ErrorWhenUserAlreadyRemoved() {
	err := suite.repo.Create(suite.user0)
	assert.Nil(suite.T(), err)

	err = suite.repo.Remove(suite.user0.Identifier)

	foundUser0, err := suite.repo.FindByIdentifier(suite.user0.Identifier)
	assert.ErrorContains(suite.T(), err, "no user found")
	assert.Nil(suite.T(), foundUser0)

	err = suite.repo.Remove(suite.user0.Identifier)

	assert.ErrorContains(suite.T(), err, "no user found")
}

func TestUserRepository(t *testing.T) {
	suite.Run(t, new(UserRepoTestSuite))
}
