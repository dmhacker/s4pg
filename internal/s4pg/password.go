package s4pg

import (
	"crypto/rand"
	"crypto/sha256"
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

func ReadPassword(message string) ([]byte, error) {
	fmt.Print(message)
	password, err := terminal.ReadPassword(int(syscall.Stdin))
	return password, err
}

func EncryptPlaintext(data []byte, password []byte) ([]byte, error) {
	// Create cipher from password
	salt := make([]byte, PBKDF2SaltLength)
	_, err := rand.Read(salt)
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
	content := cipher.Seal(nil, nonce, data, nil)
	// Encode ciphertext into byte slice
	return EncodeCiphertext(Ciphertext{
		Content: content,
		Salt:    salt,
		Nonce:   nonce,
	})
}

func DecryptCiphertext(data []byte, password []byte) ([]byte, error) {
	// Decode byte slice into ciphertext
	ciphertext, err := DecodeCiphertext(data)
	if err != nil {
		return nil, err
	}
	// Create cipher from password
	pkey := pbkdf2.Key(password, ciphertext.Salt, PBKDF2Iterations, chacha20poly1305.KeySize, sha256.New)
	cipher, err := chacha20poly1305.New(pkey)
	if err != nil {
		return nil, err
	}
	// Use cipher to decrypt all of the encrypted content
	return cipher.Open(nil, ciphertext.Nonce, ciphertext.Content, nil)
}
