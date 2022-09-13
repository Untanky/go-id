package goid

import "errors"

type MemoryUserRepository struct {
	users []*User
}

func (repo *MemoryUserRepository) FindByIdentifier(identifier string) (*User, error) {
	if repo.users == nil {
		repo.users = []*User{}
	}

	for _, user := range repo.users {
		if user.Identifier == identifier {
			return user, nil
		}
	}
	return nil, errors.New("no user found")
}

func (repo *MemoryUserRepository) Create(user *User) error {
	foundUser, err := repo.FindByIdentifier(user.Identifier)

	if foundUser != nil {
		return errors.New("user already exists")
	}

	if err != nil && err.Error() != "no user found" {
		return err
	}

	repo.users = append(repo.users, user)
	return nil
}

func (repo *MemoryUserRepository) Update(user *User) error {
	if repo.users == nil {
		repo.users = []*User{}
	}

	for index, u := range repo.users {
		if u.Identifier == user.Identifier {
			repo.users[index] = user
			return nil
		}
	}
	return errors.New("no user found")
}

func (repo *MemoryUserRepository) Remove(identifier string) error {
	if repo.users == nil {
		repo.users = []*User{}
	}

	for index, user := range repo.users {
		if user.Identifier == identifier {
			repo.users[index] = repo.users[len(repo.users)-1]
			repo.users = repo.users[:len(repo.users)-1]
			return nil
		}
	}
	return errors.New("no user found")
}
