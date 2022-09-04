package goid

import (
	"errors"
	"strings"
)

type status string

const (
	Active   = status("active")
	Inactive = status("inactive")
)

type User struct {
	Identifier string
	Passkey    string
	Status     status
}

type LoginService struct {
	userRepo UserRepository
}

func (service *LoginService) Init(userRepo UserRepository) {
	service.userRepo = userRepo
}

func (service *LoginService) findUser(identifier string) *User {
	user, err := service.userRepo.Find(identifier)

	if err != nil {
		return nil
	}

	return user
}

func (service *LoginService) Register(user *User) error {
	if err := service.validatePasskey(user.Passkey); err != nil {
		return err
	}

	if user := service.findUser(user.Identifier); user != nil {
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

func (service *LoginService) Login(identifier string, passkey string) error {
	err := errors.New("unauthorized")

	if user := service.findUser(identifier); user != nil && user.Passkey == passkey {
		if user.Status == Inactive {
			err = errors.New("user is inactive")
		} else {
			err = nil
		}
	}

	return err
}

func (service *LoginService) Activate(identifier string) error {
	user := service.findUser(identifier)

	if user == nil {
		return errors.New("no user found")
	}

	if user.Status == Active {
		return errors.New("user is already active")
	}

	user.Status = Active
	return nil
}

func (service *LoginService) Inactivate(identifier string) error {
	user := service.findUser(identifier)
	if user == nil {
		return errors.New("no user found")
	}

	if user.Status == Inactive {
		return errors.New("user is already inactive")
	}

	user.Status = Inactive
	return nil
}

func (service *LoginService) Delete(identifier string) error {
	return service.userRepo.Remove(identifier)
}
