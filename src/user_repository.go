package goid

type UserRepository interface {
	Find(identifier string) (*User, error)
	Create(user *User) error
	Update(user *User) error
	Remove(identifier string) error
}
