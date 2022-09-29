package totp_test

import (
	"testing"
	"time"

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

func (suite *TotpTestSuite) TestGenerateTotp() {
	otp0 := totp.GenerateTotp("secret", 30)
	actualOtp := totp.GenerateHotp("secret", time.Now().Unix()/30)

	assert.Equal(suite.T(), actualOtp, otp0)
}

func TestTotp(t *testing.T) {
	suite.Run(t, new(TotpTestSuite))
}
