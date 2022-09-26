package goid

type SecretString string

type KeyPair struct {
	PrivateKey SecretString
	PublicKey  SecretString
}

type Secret[Type SecretString | KeyPair] interface {
	GetSecret() Type
}

type StringSecret struct {
	value SecretString
}

func NewSecretValue(value string) Secret[SecretString] {
	return &StringSecret{value: SecretString(value)}
}

func (secret *StringSecret) GetSecret() SecretString {
	return secret.value
}

type RotatingSecret[Type SecretString | KeyPair] struct {
	currentSecret Secret[Type]
}

func NewRotatingSecret[Type SecretString | KeyPair](secret Secret[Type]) *RotatingSecret[Type] {
	return &RotatingSecret[Type]{currentSecret: secret}
}

func (secret *RotatingSecret[Type]) GetSecret() Type {
	return secret.currentSecret.GetSecret()
}

func (secret *RotatingSecret[Type]) Rotate(next Secret[Type]) {
	secret.currentSecret = next
}
