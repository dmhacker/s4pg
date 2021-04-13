package gptest

import (
	"math/rand"

	"github.com/dmhacker/s4pg/internal/s4pg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (suite *PlaintextSuite) TestCiphertextSuccessSmall() {
	raw, err := s4pg.EncodePlaintext(suite.Small)
	require.Nil(suite.T(), err)
	ct, err := s4pg.EncryptPlaintext(raw, []byte("password"))
	require.Nil(suite.T(), err)
	raw2, err := s4pg.DecryptCiphertext(ct, []byte("password"))
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), raw2)
	plaintext, err := s4pg.DecodePlaintext(raw2)
	require.Nil(suite.T(), err)
	assert.Equal(suite.T(), suite.Small, plaintext)
}

func (suite *PlaintextSuite) TestCiphertextSuccessLarge() {
	password := make([]byte, 1024)
	_, err := rand.Read(password)
	require.Nil(suite.T(), err)
	raw, err := s4pg.EncodePlaintext(suite.Large)
	require.Nil(suite.T(), err)
	ct, err := s4pg.EncryptPlaintext(raw, password)
	require.Nil(suite.T(), err)
	raw2, err := s4pg.DecryptCiphertext(ct, password)
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), raw2)
	plaintext, err := s4pg.DecodePlaintext(raw2)
	require.Nil(suite.T(), err)
	assert.Equal(suite.T(), suite.Large, plaintext)
}

func (suite *PlaintextSuite) TestCiphertextFailSmall() {
	raw, err := s4pg.EncodePlaintext(suite.Small)
	require.Nil(suite.T(), err)
	ct, err := s4pg.EncryptPlaintext(raw, []byte("password1"))
	require.Nil(suite.T(), err)
	raw2, err := s4pg.DecryptCiphertext(ct, []byte("password2"))
	require.Error(suite.T(), err)
	require.Nil(suite.T(), raw2)
}
