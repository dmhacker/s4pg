package gptest

import (
	"math/rand"
	"testing"

	"github.com/dmhacker/s4pg/internal/s4pg"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type PlaintextSuite struct {
	Small s4pg.Plaintext
	Large s4pg.Plaintext
	suite.Suite
}

func (suite *PlaintextSuite) SetupSuite() {
	suite.Small = s4pg.Plaintext{
		Content:  []byte("this is a test"),
		Filename: "small.file",
	}
	content := make([]byte, 12345678)
	_, err := rand.Read(content)
	require.Nil(suite.T(), err)
	suite.Large = s4pg.Plaintext{
		Content:  content,
		Filename: "large.file",
	}
}

func TestPlaintextSuite(t *testing.T) {
	suite.Run(t, new(PlaintextSuite))
}
