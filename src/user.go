package goid

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
