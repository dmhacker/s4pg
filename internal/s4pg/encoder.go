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

func EncodeShares(shares []Share) ([][]byte, error) {
	rawShares := make([][]byte, len(shares))
	for i, share := range shares {
		rawShare, err := EncodeShare(share)
		if err != nil {
			return nil, err
		}
		rawShares[i] = rawShare
	}
	return rawShares, nil
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

func DecodeShares(rawShares [][]byte) ([]Share, error) {
	shares := make([]Share, len(rawShares))
	for i, rawShare := range rawShares {
		share, err := DecodeShare(rawShare)
		if err != nil {
			return nil, err
		}
		shares[i] = share
	}
	return shares, nil
}
