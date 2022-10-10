package auth

import (
	"bytes"

	"golang.org/x/crypto/argon2"
)

type Encrypter interface {
	Encrypt(passkey []byte, salt []byte) []byte
	RetrieveSalt(hash []byte) []byte
}

type argon2Encrypter struct{}

func NewArgon2Encrypter() Encrypter {
	return &argon2Encrypter{}
}

func (encrypter *argon2Encrypter) Encrypt(passkey []byte, salt []byte) []byte {
	hash := argon2.IDKey(passkey, salt, 1, 64*1024, 4, 32)

	return encrypter.stashSalt(hash, salt)
}

func (encrypter *argon2Encrypter) stashSalt(hash []byte, salt []byte) []byte {
	return append(salt, append([]byte{':'}, hash...)...)
}

func (encrypter *argon2Encrypter) RetrieveSalt(hash []byte) []byte {
	return bytes.SplitN(hash, []byte{':'}, 2)[0]
}
