package goid

import (
	"errors"
	"strings"
)

type User struct {
	Identifier string
	Passkey    string
}

var KnownUsers []User

func Register(user *User) error {
	if err := validatePasskey(user.Passkey); err != nil {
		return err
	}

	for _, existingUser := range KnownUsers {
		if user.Identifier == existingUser.Identifier {
			return errors.New("Identifier already exists")
		}
	}

	KnownUsers = append(KnownUsers, *user)

	return nil
}

func validatePasskey(passkey string) error {
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

func Login(identifier string, passkey string) error {
	err := errors.New("unauthorized")

	for _, user := range KnownUsers {
		if user.Identifier == identifier && user.Passkey == passkey {
			err = nil
			break
		}
	}

	return err
}
