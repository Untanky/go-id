package goid

import (
	"errors"
)

type UserService struct {
	userRepo UserRepository
}

func (service *UserService) Init(userRepo UserRepository) {
	service.userRepo = userRepo
}

func (service *UserService) Activate(identifier string) error {
	user, err := service.userRepo.Find(identifier)

	if err != nil {
		return err
	}

	if user.Status == Active {
		return errors.New("user is already active")
	}
	service.userRepo.Update(user)

	user.Status = Active
	return nil
}

func (service *UserService) Inactivate(identifier string) error {
	user, err := service.userRepo.Find(identifier)

	if err != nil {
		return err
	}

	if user.Status == Inactive {
		return errors.New("user is already inactive")
	}

	user.Status = Inactive

	service.userRepo.Update(user)

	return nil
}

func (service *UserService) Delete(identifier string) error {
	return service.userRepo.Remove(identifier)
}
