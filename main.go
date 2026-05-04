package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	chunkSize       = 64 * 1024
	tagSize         = 16
	saltSize        = 16
	noncePrefixSize = 8
	iterations      = 100000
)

func deriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)
}

func deriveKeyWeb(password string) []byte {
	if password == "" {
		password = "rock-solid-default"
	}
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}

func encryptFile(src, dst, password string, compatMode bool) error {
	data, err := os.ReadFile(src)
	if err != nil { return err }

	if compatMode {
		key := deriveKeyWeb(password)
		block, _ := aes.NewCipher(key)
		aesgcm, _ := cipher.NewGCM(block)
		
		iv := make([]byte, 12)
		io.ReadFull(rand.Reader, iv)
		sealed := aesgcm.Seal(iv, iv, data, nil)
		return os.WriteFile(dst, sealed, 0644)
	}

	fIn, _ := os.Open(src); defer fIn.Close()
	fOut, _ := os.Create(dst); defer fOut.Close()
	
	salt := make([]byte, saltSize)
	masterNonce := make([]byte, noncePrefixSize)
	io.ReadFull(rand.Reader, salt)
	io.ReadFull(rand.Reader, masterNonce)
	
	fOut.Write(salt)
	fOut.Write(masterNonce)
	
	key := deriveKey(password, salt)
	block, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(block)
	
	buf := make([]byte, chunkSize)
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

func decryptFile(src, dst, password string, compatMode bool) error {
	data, err := os.ReadFile(src)
	if err != nil { return err }

	if compatMode {
		if len(data) < 12 { return fmt.Errorf("invalid file size") }
		key := deriveKeyWeb(password)
		block, _ := aes.NewCipher(key)
		aesgcm, _ := cipher.NewGCM(block)
		
		iv, ciphertext := data[:12], data[12:]
		plain, err := aesgcm.Open(nil, iv, ciphertext, nil)
		if err != nil { return err }
		return os.WriteFile(dst, plain, 0644)
	}

	fIn, _ := os.Open(src); defer fIn.Close()
	salt := make([]byte, saltSize)
	masterNonce := make([]byte, noncePrefixSize)
	io.ReadFull(fIn, salt)
	io.ReadFull(fIn, masterNonce)
	
	fOut, _ := os.Create(dst); defer fOut.Close()
	key := deriveKey(password, salt)
	block, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(block)
	
	fullNonce := make([]byte, 12)
	copy(fullNonce[:8], masterNonce)
	var counter uint32
	
	buf := make([]byte, chunkSize+tagSize)
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

func main() {
	mode := flag.String("m", "enc", "enc/dec")
	pass := flag.String("p", "", "password")
	input := flag.String("i", "", "input file/folder")
	output := flag.String("o", "", "output directory")
	compat := flag.Bool("compat", false, "compatibility mode for encryptor.html")
	flag.Parse()

	if *pass == "" || *input == "" || *output == "" {
		flag.Usage()
		return
	}

	filepath.WalkDir(*input, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() { return err }
		rel, _ := filepath.Rel(*input, path)
		outPath := filepath.Join(*output, rel)
		os.MkdirAll(filepath.Dir(outPath), 0755)

		if *mode == "enc" {
			return encryptFile(path, outPath+".enc", *pass, *compat)
		} else {
			return decryptFile(path, strings.TrimSuffix(outPath, ".enc"), *pass, *compat)
		}
	})
}
