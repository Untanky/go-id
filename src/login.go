package goid

import (
	"errors"
	"strings"
)

type User struct {
	Identifier string
	Passkey    string
}

type LoginService struct {
	KnownUsers []*User
}

func (service *LoginService) Register(user *User) error {
	if err := service.validatePasskey(user.Passkey); err != nil {
		return err
	}

	for _, existingUser := range service.KnownUsers {
		if user.Identifier == existingUser.Identifier {
			return errors.New("Identifier already exists")
		}
	}

	service.KnownUsers = append(service.KnownUsers, user)

	return nil
}

func (service *LoginService) validatePasskey(passkey string) error {
	if len(passkey) < 10 {
		return errors.New("Validation Error: Passkey too short")
	}

	if !strings.ContainsAny(passkey, "1234567890") {
		return errors.New("Validation Error: Passkey missing number")
	}

	if !strings.ContainsAny(passkey, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		return errors.New("Validation Error: Passkey missing uppercase character")
	}

	if !strings.ContainsAny(passkey, "abcdefghijklmnopqrstuvwxyz") {
		return errors.New("Validation Error: Passkey missing lowercase character")
	}

	if !strings.ContainsAny(passkey, "!@#$%^&**()_-+=[]{}\\|'\";:,.<>/?`~") {
		return errors.New("Validation Error: Passkey missing special character")
	}

	return nil
}

func (service *LoginService) Login(identifier string, passkey string) error {
	err := errors.New("unauthorized")

	for _, user := range service.KnownUsers {
		if user.Identifier == identifier && user.Passkey == passkey {
			err = nil
			break
		}
	}

	return err
}
