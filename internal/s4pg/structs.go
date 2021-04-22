package s4pg

type CipherType uint8
type KDFType uint8

const (
	CIPHER_CHACHA20_POLY1305 CipherType = iota
)

const (
	KDF_PBKDF2_SHA256_I500000 KDFType = iota
)

type Share struct {
	CipherType CipherType // Cipher type used to encrypt the content
	Content    []byte     // Copy of the content, encrypted using a randomly generated secret
	KeyShare   []byte     // Actual share needed to regenerate the secret key
	Nonce      []byte     // Nonce needed for the AEAD cipher
}

type Ciphertext struct {
	CipherType CipherType // Cipher type used to encrypt the content
	KDFType    KDFType    // Key derivation function type used to produce the key
	Content    []byte     // Copy of the content, encrypted using a password-derived key
	Salt       []byte     // Salt needed to derive a key from a user-inputted password
	Nonce      []byte     // Nonce needed for the AEAD cipher
}

type Plaintext struct {
	Content  []byte // Copy of the raw content without any encryption applied
	Filename string // Original filename associated with the content
}
