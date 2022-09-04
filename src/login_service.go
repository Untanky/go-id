package goid

import (
	"errors"
	"strings"
)

type LoginService struct {
	userRepo UserRepository
}

func (service *LoginService) Init(userRepo UserRepository) {
	service.userRepo = userRepo
}

func (service *LoginService) Register(user *User) error {
	if err := service.validatePasskey(user.Passkey); err != nil {
		return err
	}

	if user, _ := service.userRepo.FindByIdentifier(user.Identifier); user != nil {
		return errors.New("Identifier already exists")
	}

	service.userRepo.Create(user)

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

func (service *LoginService) Login(identifier string, passkey string) (*User, error) {
	user, foundErr := service.userRepo.FindByIdentifierAndPasskey(identifier, passkey)

	if foundErr != nil {
		return nil, errors.New("unauthorized")
	}

	if user.Status == Inactive {
		return nil, errors.New("user is inactive")
	} else {
		return user, nil
	}
}
