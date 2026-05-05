package crypto

import (
	"crypto/sha256"
	"golang.org/x/crypto/pbkdf2"
)

const (
	ChunkSize       = 64 * 1024
	TagSize         = 16
	SaltSize        = 16
	NoncePrefixSize = 8
	Iterations      = 100000
)

func Encrypt(src, dst, password string, compat bool) error {
	if compat {
		return EncryptCompat(src, dst, password)
	}
	return EncryptStandard(src, dst, password)
}

func Decrypt(src, dst, password string, compat bool) error {
	if compat {
		return DecryptCompat(src, dst, password)
	}
	return DecryptStandard(src, dst, password)
}

func DeriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, Iterations, 32, sha256.New)
}

func DeriveKeyWeb(password string) []byte {
	if password == "" {
		password = "rock-solid-default"
	}
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}