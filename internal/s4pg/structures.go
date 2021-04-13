package s4pg

type ShareContent struct {
	Content []byte // A copy of the content, encrypted using a randomly generated secret
	Share   []byte // A share needed to re-generate the randomly generated secret
	Nonce   []byte // A nonce needed for the AEAD cipher
}

type PasswordContent struct {
	Content []byte // A copy of the content, encrypted using a password-derived key
	Salt    []byte // A salt needed to derive a key from a user-inputted password
	Nonce   []byte // A nonce needed for the AEAD cipher
}

type OriginalContent struct {
	Content  []byte // A copy of the raw content without any encryption applied
	Filename string // The original filename associated with the content
}
