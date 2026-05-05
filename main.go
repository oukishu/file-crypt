package main

import (
	"github.com/oukishu/file-crypt/crypto"
	"flag"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	mode := flag.String("m", "enc", "enc/dec")
	pass := flag.String("p", "", "password")
	input := flag.String("i", "", "input file/folder")
	output := flag.String("o", "", "output directory")
	compat := flag.Bool("compat", false, "compatibility mode for WebCrypto")
	flag.Parse()

	if *pass == "" || *input == "" || *output == "" {
		flag.Usage()
		return
	}

	_ = filepath.WalkDir(*input, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() { return err }
		
		rel, _ := filepath.Rel(*input, path)
		outPath := filepath.Join(*output, rel)
		_ = os.MkdirAll(filepath.Dir(outPath), 0755)

		if *mode == "enc" {
			target := outPath + ".enc"
			if *compat {
				return crypto.EncryptCompat(path, target, *pass)
			}
			return crypto.EncryptStandard(path, target, *pass)
		} else {
			target := strings.TrimSuffix(outPath, ".enc")
			if *compat {
				return crypto.DecryptCompat(path, target, *pass)
			}
			return crypto.DecryptStandard(path, target, *pass)
		}
	})
}