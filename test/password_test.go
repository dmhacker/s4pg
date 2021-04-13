package gptest

import (
	"math/rand"

	"github.com/dmhacker/s4pg/internal/s4pg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (suite *PlaintextSuite) TestPasswordSuccessSmall() {
	raw, err := s4pg.EncodePlaintext(suite.Small)
	require.Nil(suite.T(), err)
	ciphertext, err := s4pg.EncryptPlaintext(raw, []byte("password"))
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), ciphertext)
	raw2, err := s4pg.DecryptCiphertext(ciphertext, []byte("password"))
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), raw2)
	plaintext, err := s4pg.DecodePlaintext(raw2)
	require.Nil(suite.T(), err)
	assert.Equal(suite.T(), suite.Small, plaintext)
}

func (suite *PlaintextSuite) TestPasswordSuccessLarge() {
	password := make([]byte, 1024)
	_, err := rand.Read(password)
	require.Nil(suite.T(), err)
	raw, err := s4pg.EncodePlaintext(suite.Large)
	require.Nil(suite.T(), err)
	ciphertext, err := s4pg.EncryptPlaintext(raw, password)
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), ciphertext)
	raw2, err := s4pg.DecryptCiphertext(ciphertext, password)
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), raw2)
	plaintext, err := s4pg.DecodePlaintext(raw2)
	require.Nil(suite.T(), err)
	assert.Equal(suite.T(), suite.Large, plaintext)
}

func (suite *PlaintextSuite) TestPasswordFailSmall() {
	raw, err := s4pg.EncodePlaintext(suite.Small)
	require.Nil(suite.T(), err)
	ciphertext, err := s4pg.EncryptPlaintext(raw, []byte("password1"))
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), ciphertext)
	raw2, err := s4pg.DecryptCiphertext(ciphertext, []byte("password2"))
	require.Error(suite.T(), err)
	require.Nil(suite.T(), raw2)
}
