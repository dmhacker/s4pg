package s4pg

import (
    "bytes"
    "encoding/gob"
)

func EncodePlaintext(plaintext Plaintext) ([]byte, error) {
    writer := new(bytes.Buffer)
	encoder := gob.NewEncoder(writer)
	err := encoder.Encode(plaintext)
    return writer.Bytes(), err
}

func EncodeCiphertext(ciphertext Ciphertext) ([]byte, error) {
    writer := new(bytes.Buffer)
	encoder := gob.NewEncoder(writer)
	err := encoder.Encode(ciphertext)
    return writer.Bytes(), err
}

func EncodeShare(share Share) ([]byte, error) {
    writer := new(bytes.Buffer)
	encoder := gob.NewEncoder(writer)
	err := encoder.Encode(share)
    return writer.Bytes(), err
}

func DecodePlaintext(raw []byte) (Plaintext, error) {
    var plaintext Plaintext
    reader := bytes.NewBuffer(raw)
	decoder := gob.NewDecoder(reader)
    err := decoder.Decode(&plaintext)
    return plaintext, err
}

func DecodeCiphertext(raw []byte) (Ciphertext, error) {
    var ciphertext Ciphertext
    reader := bytes.NewBuffer(raw)
	decoder := gob.NewDecoder(reader)
    err := decoder.Decode(&ciphertext)
    return ciphertext, err
}

func DecodeShare(raw []byte) (Share, error) {
    var share Share
    reader := bytes.NewBuffer(raw)
	decoder := gob.NewDecoder(reader)
    err := decoder.Decode(&share)
    return share, err
}
