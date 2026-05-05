package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
)

func EncryptCompat(src, dst, password string) error {
	data, err := os.ReadFile(src)
	if err != nil { return err }

	key := DeriveKeyWeb(password)
	block, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(block)
	
	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil { return err }
	
	sealed := aesgcm.Seal(iv, iv, data, nil)
	return os.WriteFile(dst, sealed, 0644)
}

func DecryptCompat(src, dst, password string) error {
	data, err := os.ReadFile(src)
	if err != nil { return err }

	if len(data) < 12 { return fmt.Errorf("invalid compat file size") }
	
	key := DeriveKeyWeb(password)
	block, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(block)
	
	iv, ciphertext := data[:12], data[12:]
	plain, err := aesgcm.Open(nil, iv, ciphertext, nil)
	if err != nil { return fmt.Errorf("compat decryption failed: %v", err) }
	
	return os.WriteFile(dst, plain, 0644)
}