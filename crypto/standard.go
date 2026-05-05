package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

func EncryptStandard(src, dst, password string) error {
	fIn, err := os.Open(src); if err != nil { return err }
	defer fIn.Close()
	
	fOut, err := os.Create(dst); if err != nil { return err }
	defer fOut.Close()
	
	salt := make([]byte, SaltSize)
	masterNonce := make([]byte, NoncePrefixSize)
	io.ReadFull(rand.Reader, salt)
	io.ReadFull(rand.Reader, masterNonce)
	
	fOut.Write(salt)
	fOut.Write(masterNonce)
	
	key := DeriveKey(password, salt)
	block, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(block)
	
	buf := make([]byte, ChunkSize)
	fullNonce := make([]byte, 12)
	copy(fullNonce[:8], masterNonce)
	var counter uint32
	
	for {
		n, err := fIn.Read(buf)
		if n > 0 {
			binary.BigEndian.PutUint32(fullNonce[8:], counter)
			sealed := aesgcm.Seal(nil, fullNonce, buf[:n], nil)
			fOut.Write(sealed)
			counter++
		}
		if err == io.EOF { break }
		if err != nil { return err }
	}
	return nil
}

func DecryptStandard(src, dst, password string) error {
	fIn, err := os.Open(src); if err != nil { return err }
	defer fIn.Close()

	salt := make([]byte, SaltSize)
	masterNonce := make([]byte, NoncePrefixSize)
	if _, err := io.ReadFull(fIn, salt); err != nil { return err }
	if _, err := io.ReadFull(fIn, masterNonce); err != nil { return err }
	
	fOut, err := os.Create(dst); if err != nil { return err }
	defer fOut.Close()

	key := DeriveKey(password, salt)
	block, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(block)
	
	fullNonce := make([]byte, 12)
	copy(fullNonce[:8], masterNonce)
	var counter uint32
	
	buf := make([]byte, ChunkSize+TagSize)
	for {
		n, err := fIn.Read(buf)
		if n > 0 {
			binary.BigEndian.PutUint32(fullNonce[8:], counter)
			plain, err := aesgcm.Open(nil, fullNonce, buf[:n], nil)
			if err != nil { return fmt.Errorf("integrity check failed") }
			fOut.Write(plain)
			counter++
		}
		if err == io.EOF { break }
	}
	return nil
}