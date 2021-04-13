package gptest

import (
    "math/rand"
	"testing"

	"github.com/dmhacker/s4pg/internal/s4pg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type PasswordSuite struct {
	suite.Suite
}

func (suite *PasswordSuite) SetupSuite() {
}

func (suite *PasswordSuite) TestEncryptDecryptSmall() {
	ocontent := s4pg.OriginalContent{
		Content:  []byte("this is a test"),
		Filename: "test",
	}
	pcontent, err := s4pg.PasswordEncrypt([]byte("password"), &ocontent)
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), pcontent)
	ocontent2, err := s4pg.PasswordDecrypt([]byte("password"), pcontent)
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), ocontent2)
	assert.Equal(suite.T(), ocontent2.Content, ocontent.Content)
	assert.Equal(suite.T(), ocontent2.Filename, ocontent.Filename)
}

func (suite *PasswordSuite) TestEncryptDecryptLarge() {
    content := make([]byte, 12345678)
    _, err := rand.Read(content)
	require.Nil(suite.T(), err)
    password := make([]byte, 1024)
    _, err = rand.Read(password)
	require.Nil(suite.T(), err)
    ocontent := s4pg.OriginalContent{
		Content:  content,
		Filename: "test",
	}
	pcontent, err := s4pg.PasswordEncrypt(password, &ocontent)
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), pcontent)
	ocontent2, err := s4pg.PasswordDecrypt(password, pcontent)
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), ocontent2)
	assert.Equal(suite.T(), ocontent2.Content, ocontent.Content)
	assert.Equal(suite.T(), ocontent2.Filename, ocontent.Filename)
}

func (suite *PasswordSuite) TestEncryptDecryptFail() {
	ocontent := s4pg.OriginalContent{
		Content:  []byte("this is a test"),
		Filename: "test",
	}
	pcontent, err := s4pg.PasswordEncrypt([]byte("password1"), &ocontent)
	require.Nil(suite.T(), err)
	require.NotNil(suite.T(), pcontent)
	ocontent2, err := s4pg.PasswordDecrypt([]byte("password2"), pcontent)
	require.Error(suite.T(), err)
	require.Nil(suite.T(), ocontent2)
}

func TestPasswordSuite(t *testing.T) {
	suite.Run(t, new(PasswordSuite))
}
