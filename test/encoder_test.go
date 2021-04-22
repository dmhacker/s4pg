package gptest

import (
	"math/rand"

	"github.com/dmhacker/s4pg/internal/s4pg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (suite *PlaintextSuite) TestSmallPlaintextEncodeDecodeSuccess() {
	ptBytes, err := s4pg.EncodePlaintext(suite.Small)
	require.Nil(suite.T(), err)
	pt, err := s4pg.DecodePlaintext(ptBytes)
	require.Nil(suite.T(), err)
	assert.Equal(suite.T(), suite.Small, pt)
}

func (suite *PlaintextSuite) TestLargePlaintextEncodeDecodeSuccess() {
	ptBytes, err := s4pg.EncodePlaintext(suite.Large)
	require.Nil(suite.T(), err)
	pt, err := s4pg.DecodePlaintext(ptBytes)
	require.Nil(suite.T(), err)
	assert.Equal(suite.T(), suite.Large, pt)
}

func (suite *PlaintextSuite) TestLargeCiphertextEncodeDecodeSuccess() {
	oct := s4pg.Ciphertext{
		Content:    make([]byte, 10000),
		Salt:       make([]byte, 8),
		Nonce:      make([]byte, 32),
		CipherType: s4pg.CIPHER_CHACHA20_POLY1305,
		KDFType:    s4pg.KDF_PBKDF2_SHA256_I500000,
	}
	_, err := rand.Read(oct.Content)
	require.Nil(suite.T(), err)
	_, err = rand.Read(oct.Nonce)
	require.Nil(suite.T(), err)
	_, err = rand.Read(oct.Salt)
	require.Nil(suite.T(), err)
	ctBytes, err := s4pg.EncodeCiphertext(oct)
	require.Nil(suite.T(), err)
	ct, err := s4pg.DecodeCiphertext(ctBytes)
	require.Nil(suite.T(), err)
	assert.Equal(suite.T(), oct, ct)
}

func (suite *PlaintextSuite) TestLargeShareEncodeDecodeSuccess() {
	oshare := s4pg.Share{
		Content:    make([]byte, 10000),
		KeyShare:   make([]byte, 32),
		Nonce:      make([]byte, 32),
		CipherType: s4pg.CIPHER_CHACHA20_POLY1305,
	}
	_, err := rand.Read(oshare.Content)
	require.Nil(suite.T(), err)
	_, err = rand.Read(oshare.Nonce)
	require.Nil(suite.T(), err)
	_, err = rand.Read(oshare.KeyShare)
	require.Nil(suite.T(), err)
	shareBytes, err := s4pg.EncodeShare(oshare)
	require.Nil(suite.T(), err)
	share, err := s4pg.DecodeShare(shareBytes)
	require.Nil(suite.T(), err)
	assert.Equal(suite.T(), oshare, share)
}

func (suite *PlaintextSuite) TestLargeSharesEncodeDecodeSuccess() {
	oshares := make([]s4pg.Share, 7)
	for i := 0; i < 7; i++ {
		oshare := s4pg.Share{
			Content:    make([]byte, 10000),
			KeyShare:   make([]byte, 32),
			Nonce:      make([]byte, 32),
			CipherType: s4pg.CIPHER_CHACHA20_POLY1305,
		}
		_, err := rand.Read(oshare.Content)
		require.Nil(suite.T(), err)
		_, err = rand.Read(oshare.Nonce)
		require.Nil(suite.T(), err)
		_, err = rand.Read(oshare.KeyShare)
		require.Nil(suite.T(), err)
		oshares[i] = oshare
	}
	shareBytes, err := s4pg.EncodeShares(oshares)
	require.Nil(suite.T(), err)
	shares, err := s4pg.DecodeShares(shareBytes)
	require.Nil(suite.T(), err)
	assert.Equal(suite.T(), oshares, shares)
}
