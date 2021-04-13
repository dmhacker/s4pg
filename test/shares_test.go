package gptest

import (
	"github.com/dmhacker/s4pg/internal/s4pg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (suite *PlaintextSuite) TestSmallSharesSplitCombineAll() {
	raw, err := s4pg.EncodePlaintext(suite.Small)
	require.Nil(suite.T(), err)
	shares, err := s4pg.SplitShares(raw, 5, 3)
	require.Nil(suite.T(), err)
	raw2, err := s4pg.CombineShares(shares)
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), raw2)
	plaintext, err := s4pg.DecodePlaintext(raw2)
	require.Nil(suite.T(), err)
	assert.Equal(suite.T(), suite.Small, plaintext)
}

func (suite *PlaintextSuite) TestSmallSharesSplitCombineThreshold() {
	raw, err := s4pg.EncodePlaintext(suite.Small)
	require.Nil(suite.T(), err)
	shares, err := s4pg.SplitShares(raw, 5, 3)
	require.Nil(suite.T(), err)
	for i := 0; i < 2; i++ {
		raw2, err := s4pg.CombineShares(shares[i:(i + 3)])
		require.Nil(suite.T(), err)
		require.NotNil(suite.T(), raw2)
		plaintext, err := s4pg.DecodePlaintext(raw2)
		require.Nil(suite.T(), err)
		assert.Equal(suite.T(), suite.Small, plaintext)
	}
}

func (suite *PlaintextSuite) TestSmallSharesSplitCombineFail() {
	raw, err := s4pg.EncodePlaintext(suite.Small)
	require.Nil(suite.T(), err)
	shares, err := s4pg.SplitShares(raw, 5, 3)
	require.Nil(suite.T(), err)
	for i := 0; i < 3; i++ {
		_, err = s4pg.CombineShares(shares[i:(i + 2)])
		require.Error(suite.T(), err)
	}
}

func (suite *PlaintextSuite) TestLargeSharesSplitCombineThreshold() {
	raw, err := s4pg.EncodePlaintext(suite.Large)
	require.Nil(suite.T(), err)
	shares, err := s4pg.SplitShares(raw, 100, 67)
	require.Nil(suite.T(), err)
	raw2, err := s4pg.CombineShares(shares[25:92])
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), raw2)
	plaintext, err := s4pg.DecodePlaintext(raw2)
	require.Nil(suite.T(), err)
	assert.Equal(suite.T(), suite.Large, plaintext)
}

func (suite *PlaintextSuite) TestLargeSharesSplitCombineFail() {
	raw, err := s4pg.EncodePlaintext(suite.Large)
	require.Nil(suite.T(), err)
	shares, err := s4pg.SplitShares(raw, 100, 67)
	require.Nil(suite.T(), err)
	_, err = s4pg.CombineShares(shares[25:91])
	require.Error(suite.T(), err)
}
