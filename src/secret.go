package goid

type Secret interface {
	GetSecret() []byte
}

type RotatingSecret interface {
	Secret
	RotateSecret(nextValue []byte)
}

type StringSecret struct {
	value []byte
}

func NewSecretValue(value []byte) RotatingSecret {
	return &StringSecret{value: value}
}

func (secret *StringSecret) GetSecret() []byte {
	return secret.value
}

func (secret *StringSecret) RotateSecret(nextValue []byte) {
	secret.value = nextValue
}
