package auth

import (
	"errors"
	"strings"

	. "github.com/Untanky/go-id/user"
)

type LoginService struct {
	userRepo  UserRepository
	encrypter Encrypter
}

func (service *LoginService) Init(userRepo UserRepository, encrypter Encrypter) {
	service.userRepo = userRepo
	service.encrypter = encrypter
}

func (service *LoginService) Register(user *User) error {
	if err := service.validatePasskey(user.Passkey); err != nil {
		return err
	}

	user.Passkey = string(service.encrypter.Encrypt([]byte(user.Passkey), []byte("salt")))

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
	user, foundErr := service.userRepo.FindByIdentifier(identifier)

	if foundErr != nil {
		return nil, errors.New("unauthorized")
	}

	if user.Status == Inactive {
		return nil, errors.New("user is inactive")
	}

	salt := service.encrypter.RetrieveSalt([]byte(user.Passkey))
	encrptedPasskey := string(service.encrypter.Encrypt([]byte(passkey), salt))

	if encrptedPasskey != user.Passkey {
		return nil, errors.New("unauthorized")
	}

	return user, nil
}
