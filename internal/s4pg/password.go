package s4pg

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"syscall"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	PBKDF2SaltLength = 8
	PBKDF2Iterations = 10000
)

func PasswordRead(message string) ([]byte, error) {
	fmt.Print(message)
	password, err := terminal.ReadPassword(int(syscall.Stdin))
	return password, err
}

func PasswordEncrypt(password []byte, ocontent *OriginalContent) (*PasswordContent, error) {
	// Encode original content struct into bytes
	writer := new(bytes.Buffer)
	encoder := gob.NewEncoder(writer)
	err := encoder.Encode(ocontent)
	if err != nil {
		return nil, err
	}
	raw := writer.Bytes()
	defer Shred(raw)
	// Create cipher from password
	salt := make([]byte, PBKDF2SaltLength)
	_, err = rand.Read(salt)
	if err != nil {
		return nil, err
	}
	pkey := pbkdf2.Key(password, salt, PBKDF2Iterations, chacha20poly1305.KeySize, sha256.New)
	cipher, err := chacha20poly1305.New(pkey)
	if err != nil {
		return nil, err
	}
	// Use cipher to encrypt all of the original content
	nonce := make([]byte, chacha20poly1305.NonceSize)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	content := cipher.Seal(nil, nonce, raw, nil)
	return &PasswordContent{
		Content: content,
		Salt:    salt,
		Nonce:   nonce,
	}, nil
}

func PasswordDecrypt(password []byte, pcontent *PasswordContent) (*OriginalContent, error) {
	// Create cipher from password
	pkey := pbkdf2.Key(password, pcontent.Salt, PBKDF2Iterations, chacha20poly1305.KeySize, sha256.New)
	cipher, err := chacha20poly1305.New(pkey)
	if err != nil {
		return nil, err
	}
	// Use cipher to decrypt all of the encrypted content
	raw, err := cipher.Open(nil, pcontent.Nonce, pcontent.Content, nil)
	if err != nil {
		return nil, err
	}
    defer Shred(raw)
	// Decode raw data into original content struct
	var original OriginalContent
	reader := bytes.NewBuffer(raw)
	decoder := gob.NewDecoder(reader)
	err = decoder.Decode(&original)
	if err != nil {
		return nil, err
	}
	return &original, nil
}
