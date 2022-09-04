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
			if user.Status == Inactive {
				err = errors.New("user is inactive")
			} else {
				err = nil
			}
			break
		}
	}

	return err
}

func (service *LoginService) Activate(identifier string) error {
	for _, user := range service.KnownUsers {
		if user.Identifier == identifier {
			if user.Status == Active {
				return errors.New("user is already active")
			}
			user.Status = Active
			return nil
		}
	}

	return errors.New("no user found")
}

func (service *LoginService) Inactivate(identifier string) error {
	for _, user := range service.KnownUsers {
		if user.Identifier == identifier {
			if user.Status == Inactive {
				return errors.New("user is already inactive")
			}
			user.Status = Inactive
			return nil
		}
	}
	return errors.New("no user found")
}
