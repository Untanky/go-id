package goid

import "errors"

type User struct {
	Identifier string
	Passkey    string
}

var KnownUsers []User

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
