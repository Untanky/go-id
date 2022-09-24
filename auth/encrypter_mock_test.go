package auth_test

import (
	"bytes"

	"github.com/stretchr/testify/mock"
)

type MockEncrypter struct {
	mock.Mock
}

func (m *MockEncrypter) Encrypt(passkey []byte, salt []byte) []byte {
	args := m.Called(passkey, salt)
	hash := []byte(args.String(0))

	return append(salt, append([]byte{':'}, hash...)...)
}

func (m *MockEncrypter) stashSalt(hash []byte, salt []byte) []byte {
	return append(salt, append([]byte{':'}, hash...)...)
}

func (m *MockEncrypter) RetrieveSalt(hash []byte) []byte {
	return bytes.SplitN(hash, []byte{':'}, 2)[0]
}
