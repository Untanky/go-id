package user

type UserRepository interface {
	FindByIdentifier(identifier string) (*User, error)
	Create(user *User) error
	Update(user *User) error
	Remove(identifier string) error
}
