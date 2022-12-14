package totp_test

import (
	"testing"

	"github.com/Untanky/go-id/secret"
	"github.com/Untanky/go-id/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type TotpServiceTestSuite struct {
	suite.Suite
	service *totp.OtpService
	secret  secret.Secret[secret.SecretString]
}

func (suite *TotpServiceTestSuite) SetupTest() {
	suite.service = new(totp.OtpService)
	suite.service.Init(30)
	suite.secret = secret.NewSecretValue("secret")
}

func (suite *TotpServiceTestSuite) TestGenerateOtp_ForMfaChallenge() {
	challenge := totp.Challenge{
		ChallengeType: totp.MFA_CHALLENGE,
		Secret:        suite.secret,
	}

	otp := suite.service.GenerateOtp(challenge)

	assert.Equal(suite.T(), totp.GenerateTotp("secret", 30), otp)
}

func (suite *TotpServiceTestSuite) TestGenerateOtp_ForSmsChallenge() {
	challenge := totp.Challenge{
		ChallengeType: totp.SMS_CHALLENGE,
		Secret:        suite.secret,
		Event:         0,
	}

	otp := suite.service.GenerateOtp(challenge)

	assert.Equal(suite.T(), "328482", otp)
}

func (suite *TotpServiceTestSuite) TestGenerateOtp_ForEmailChallenge() {
	challenge := totp.Challenge{
		ChallengeType: totp.EMAIL_CHALLENGE,
		Secret:        suite.secret,
		Event:         0,
	}

	otp := suite.service.GenerateOtp(challenge)

	assert.Equal(suite.T(), "328482", otp)
}

func (suite *TotpServiceTestSuite) TestValidateOtp_ForMfaChallenge() {
	challenge := totp.Challenge{
		ChallengeType: totp.MFA_CHALLENGE,
		Secret:        suite.secret,
	}
	incorrectOtp := "000000"
	correctOtp := suite.service.GenerateOtp(challenge)

	notOk := suite.service.ValidateOtp(incorrectOtp, challenge)
	ok := suite.service.ValidateOtp(correctOtp, challenge)

	assert.True(suite.T(), ok)
	assert.False(suite.T(), notOk)
}

func (suite *TotpServiceTestSuite) TestValidateOtp_ForSmsChallenge() {
	challenge := totp.Challenge{
		ChallengeType: totp.SMS_CHALLENGE,
		Secret:        suite.secret,
		Event:         0,
	}
	incorrectOtp := "000000"
	correctOtp := "328482"

	notOk := suite.service.ValidateOtp(incorrectOtp, challenge)
	ok := suite.service.ValidateOtp(correctOtp, challenge)

	assert.True(suite.T(), ok)
	assert.False(suite.T(), notOk)
}

func (suite *TotpServiceTestSuite) TestValidateOtp_ForEmailChallenge() {
	challenge := totp.Challenge{
		ChallengeType: totp.EMAIL_CHALLENGE,
		Secret:        suite.secret,
		Event:         0,
	}
	incorrectOtp := "000000"
	correctOtp := "328482"

	notOk := suite.service.ValidateOtp(incorrectOtp, challenge)
	ok := suite.service.ValidateOtp(correctOtp, challenge)

	assert.True(suite.T(), ok)
	assert.False(suite.T(), notOk)
}

func TestTotpService(t *testing.T) {
	suite.Run(t, new(TotpServiceTestSuite))
}
