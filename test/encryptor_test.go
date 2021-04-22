package gptest

import (
	"math/rand"

	"github.com/dmhacker/s4pg/internal/s4pg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (suite *PlaintextSuite) TestSmallCiphertextEncryptDecryptSuccess() {
	raw, err := s4pg.EncodePlaintext(suite.Small)
	require.Nil(suite.T(), err)
	ct, err := s4pg.EncryptCiphertext(raw, []byte("password"))
	require.Nil(suite.T(), err)
	assert.Equal(suite.T(), ct.CipherType, s4pg.CIPHER_CHACHA20_POLY1305)
	assert.Equal(suite.T(), ct.KDFType, s4pg.KDF_PBKDF2_SHA256_I500000)
	raw2, err := s4pg.DecryptCiphertext(ct, []byte("password"))
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), raw2)
	plaintext, err := s4pg.DecodePlaintext(raw2)
	require.Nil(suite.T(), err)
	assert.Equal(suite.T(), suite.Small, plaintext)
}

func (suite *PlaintextSuite) TestLargeCiphertextEncryptDecryptSuccess() {
	password := make([]byte, 1024)
	_, err := rand.Read(password)
	require.Nil(suite.T(), err)
	raw, err := s4pg.EncodePlaintext(suite.Large)
	require.Nil(suite.T(), err)
	ct, err := s4pg.EncryptCiphertext(raw, password)
	assert.Equal(suite.T(), ct.CipherType, s4pg.CIPHER_CHACHA20_POLY1305)
	assert.Equal(suite.T(), ct.KDFType, s4pg.KDF_PBKDF2_SHA256_I500000)
	require.Nil(suite.T(), err)
	raw2, err := s4pg.DecryptCiphertext(ct, password)
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), raw2)
	plaintext, err := s4pg.DecodePlaintext(raw2)
	require.Nil(suite.T(), err)
	assert.Equal(suite.T(), suite.Large, plaintext)
}

func (suite *PlaintextSuite) TestSmallCiphertextEncryptDecryptFail() {
	raw, err := s4pg.EncodePlaintext(suite.Small)
	require.Nil(suite.T(), err)
	ct, err := s4pg.EncryptCiphertext(raw, []byte("password1"))
	assert.Equal(suite.T(), ct.CipherType, s4pg.CIPHER_CHACHA20_POLY1305)
	assert.Equal(suite.T(), ct.KDFType, s4pg.KDF_PBKDF2_SHA256_I500000)
	require.Nil(suite.T(), err)
	_, err = s4pg.DecryptCiphertext(ct, []byte("password2"))
	require.Error(suite.T(), err)
}
