package s4pg

type Share struct {
	Content  []byte // Copy of the content, encrypted using a randomly generated secret
	KeyShare []byte // Actual share needed to regenerate the secret key
	Nonce    []byte // Nonce needed for the AEAD cipher
}

type Ciphertext struct {
	Content []byte // Copy of the content, encrypted using a password-derived key
	Salt    []byte // Salt needed to derive a key from a user-inputted password
	Nonce   []byte // Nonce needed for the AEAD cipher
}

type Plaintext struct {
	Content  []byte // Copy of the raw content without any encryption applied
	Filename string // Original filename associated with the content
}
