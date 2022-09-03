package goid_test

import (
	"testing"

	. "github.com/Untanky/go-id/src"
	"github.com/stretchr/testify/assert"
)

const (
	knownUserId   = "knownUser"
	knownUserKey  = "xyz"
	unknownUserId = "unknownUser"
)

func TestLogin_LoginWithKnownUser(t *testing.T) {
	var err error

	err = Login(knownUserId, knownUserKey)

	assert.Nil(t, err)
}

func TestLogin_LoginWithKnownUserWithIncorrectPassword(t *testing.T) {
	var err error

	err = Login(knownUserId, knownUserKey+"!")

	assert.ErrorContains(t, err, "unauthorized")
}

func TestLogin_LoginWithUnknownUser(t *testing.T) {
	err := Login(unknownUserId, "xyz")

	assert.ErrorContains(t, err, "unauthorized")
}
