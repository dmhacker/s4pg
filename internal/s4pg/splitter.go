package s4pg

import (
	"crypto/rand"
	"fmt"

	"github.com/awnumar/memguard"
	"github.com/hashicorp/vault/shamir"
	"golang.org/x/crypto/chacha20poly1305"
)

func SplitShares(raw []byte, count int, threshold int) ([]Share, error) {
	// Generate secret key securely
	skeyEnclave := memguard.NewEnclaveRandom(chacha20poly1305.KeySize)
	skey, err := skeyEnclave.Open()
	if err != nil {
		return nil, err
	}
	defer skey.Destroy()
	// Encrypt content using secret key
	nonce := make([]byte, chacha20poly1305.NonceSize)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	cipher, err := chacha20poly1305.New(skey.Bytes())
	if err != nil {
		return nil, err
	}
	content := cipher.Seal(nil, nonce, raw, nil)
	// Split secret key using SSSS
	skeyShares, err := shamir.Split(skey.Bytes(), count, threshold)
	if err != nil {
		return nil, err
	}
	// Encode full shares as byte slices
	shares := make([]Share, len(skeyShares))
	for i, skeyShare := range skeyShares {
		shares[i] = Share{
			CipherType: CIPHER_CHACHA20_POLY1305,
			Content:    content,
			KeyShare:   skeyShare,
			Nonce:      nonce,
		}
	}
	return shares, nil
}

func CombineShares(rawShares []Share) ([]byte, error) {
	if len(rawShares) == 0 {
		return nil, fmt.Errorf("no shares specified")
	}
	var content []byte
	var nonce []byte
	var cipherType CipherType
	skeyShares := make([][]byte, len(rawShares))
	for i, share := range rawShares {
		if i == 0 {
			content = share.Content
			nonce = share.Nonce
			cipherType = share.CipherType
		}
		skeyShares[i] = share.KeyShare
	}
	skeyRaw, err := shamir.Combine(skeyShares)
	if err != nil {
		return nil, err
	}
	skeyEnclave := memguard.NewEnclave(skeyRaw)
	skey, err := skeyEnclave.Open()
	if err != nil {
		return nil, err
	}
	defer skey.Destroy()
	switch cipherType {
	case CIPHER_CHACHA20_POLY1305:
		cipher, err := chacha20poly1305.New(skey.Bytes())
		if err != nil {
			return nil, err
		}
		return cipher.Open(nil, nonce, content, nil)
	}
	return nil, fmt.Errorf("unknown cipher specified")
}
