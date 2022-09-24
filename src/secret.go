package goid

type Secret[SecretType any] interface {
	GetSecret() SecretType
}

type RotatingSecret[SecretType any] interface {
	Secret[SecretType]
	RotateSecret(nextValue SecretType)
}

type StringSecret struct {
	value []byte
}

func NewSecretValue(value []byte) RotatingSecret[[]byte] {
	return &StringSecret{value: value}
}

func (secret *StringSecret) GetSecret() []byte {
	return secret.value
}

func (secret *StringSecret) RotateSecret(nextValue []byte) {
	secret.value = nextValue
}
