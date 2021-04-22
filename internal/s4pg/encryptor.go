package s4pg

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

func EncryptCiphertext(raw []byte, password []byte) (Ciphertext, error) {
	var ct Ciphertext
	// Create key from password
	ct.KDFType = KDF_PBKDF2_SHA256_I500000
	ct.Salt = make([]byte, 8)
	_, err := rand.Read(ct.Salt)
	if err != nil {
		return ct, err
	}
	pkeyEnclave := memguard.NewEnclave(pbkdf2.Key(password, ct.Salt, 500000, chacha20poly1305.KeySize, sha256.New))
	pkey, err := pkeyEnclave.Open()
	if err != nil {
		return ct, err
	}
	defer pkey.Destroy()
	// Create cipher from password key
	ct.CipherType = CIPHER_CHACHA20_POLY1305
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
	// Create key from password
	var pkeyEnclave *memguard.Enclave
	switch ct.KDFType {
	case KDF_PBKDF2_SHA256_I500000:
		pkeyEnclave = memguard.NewEnclave(pbkdf2.Key(password, ct.Salt, 500000, chacha20poly1305.KeySize, sha256.New))
	default:
		return nil, fmt.Errorf("unknown kdf specified")
	}
	pkey, err := pkeyEnclave.Open()
	if err != nil {
		return nil, err
	}
	defer pkey.Destroy()
	// Create cipher from password key
	var ciph cipher.AEAD
	switch ct.CipherType {
	case CIPHER_CHACHA20_POLY1305:
		ciph, err = chacha20poly1305.New(pkey.Bytes())
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown cipher specified")
	}
	// Use cipher to decrypt content
	return ciph.Open(nil, ct.Nonce, ct.Content, nil)
}
