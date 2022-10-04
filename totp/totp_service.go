package totp

import "github.com/Untanky/go-id/secret"

type challengeType string

const (
	SMS_CHALLENGE   challengeType = "SMS_CHALLENGE"
	EMAIL_CHALLENGE challengeType = "EMAIL_CHALLENGE"
	MFA_CHALLENGE   challengeType = "MFA_CHALLENGE"
)

type Challenge struct {
	ChallengeType challengeType
	Secret        secret.Secret[secret.SecretString]
	Event         int64
}

type OtpService struct {
	interval int64
}

func (service *OtpService) Init(interval int64) {
	service.interval = interval
}

func (service *OtpService) GenerateOtp(challenge Challenge) string {
	switch challenge.ChallengeType {
	case SMS_CHALLENGE:
		fallthrough
	case EMAIL_CHALLENGE:
		return GenerateHotp(string(challenge.Secret.GetSecret()), challenge.Event)
	case MFA_CHALLENGE:
		return GenerateTotp(string(challenge.Secret.GetSecret()), service.interval)
	}
	return ""
}

func (service *OtpService) ValidateOtp(actualOtp string, challenge Challenge) bool {
	expectedOtp := service.GenerateOtp(challenge)

	return expectedOtp == actualOtp
}
