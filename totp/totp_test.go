package totp_test

import (
	"testing"

	"github.com/Untanky/go-id/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type TotpTestSuite struct {
	suite.Suite
}

func (suite *TotpTestSuite) TestGenerateHotp() {
	otp0 := totp.GenerateHotp("secret", 30)
	otp1 := totp.GenerateHotp("secret", 31)

	assert.Equal(suite.T(), "471360", otp0)
	assert.Equal(suite.T(), "691505", otp1)
}

func TestTotp(t *testing.T) {
	suite.Run(t, new(TotpTestSuite))
}
