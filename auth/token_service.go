package auth

import (
	"encoding/json"
	"fmt"
	"time"
)

type Jwt string

type TokenService struct {
}

func (service *TokenService) CreateRefreshToken(subject string, session string) (string, error) {
	payload := map[string]interface{}{
		"sub": subject,
		"sid": session,
		"iat": time.Now().Unix(),
		"exp": time.Now().AddDate(1, 0, 0).Unix(),
	}
	payloadBytes, _ := json.Marshal(payload)
	return fmt.Sprintf(".%s.", string(payloadBytes)), nil
}
