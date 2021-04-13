package s4pg

import (
	"crypto/rand"
	"crypto/sha256"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

const (
	PBKDF2SaltLength = 8
	PBKDF2Iterations = 500000
)

func EncryptCiphertext(raw []byte, password []byte) (Ciphertext, error) {
	var ct Ciphertext
	// Create cipher from password
	ct.Salt = make([]byte, PBKDF2SaltLength)
	_, err := rand.Read(ct.Salt)
	if err != nil {
		return ct, err
	}
	pkeyEnclave := memguard.NewEnclave(pbkdf2.Key(password, ct.Salt, PBKDF2Iterations, chacha20poly1305.KeySize, sha256.New))
	pkey, err := pkeyEnclave.Open()
	if err != nil {
		return ct, err
	}
	defer pkey.Destroy()
	cipher, err := chacha20poly1305.New(pkey.Bytes())
	if err != nil {
		return ct, err
	}
	// Use cipher to encrypt all of the original content
	ct.Nonce = make([]byte, chacha20poly1305.NonceSize)
	_, err = rand.Read(ct.Nonce)
	if err != nil {
		return ct, err
	}
	ct.Content = cipher.Seal(nil, ct.Nonce, raw, nil)
	return ct, nil
}

func DecryptCiphertext(ct Ciphertext, password []byte) ([]byte, error) {
	// Create cipher from password
	pkeyEnclave := memguard.NewEnclave(pbkdf2.Key(password, ct.Salt, PBKDF2Iterations, chacha20poly1305.KeySize, sha256.New))
	pkey, err := pkeyEnclave.Open()
	if err != nil {
		return nil, err
	}
	defer pkey.Destroy()
	cipher, err := chacha20poly1305.New(pkey.Bytes())
	if err != nil {
		return nil, err
	}
	// Use cipher to decrypt all of the encrypted content
	return cipher.Open(nil, ct.Nonce, ct.Content, nil)
}
