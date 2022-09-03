package goid

import "errors"

func Login(identifier string, passkey string) error {
	if identifier == "knownUser" && passkey == "xyz" {
		return nil
	}
	return errors.New("unauthorized")
}
