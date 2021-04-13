package s4pg

import (
	"fmt"
	"reflect"
)

func RunSplit(inputPath string, count int, threshold int) error {
	pt, err := ReadPlaintext(inputPath)
	if err != nil {
		return err
	}
	rawPt, err := EncodePlaintext(pt)
	if err != nil {
		return err
	}
	password, err := ReadPassword("Password: ")
	if err != nil {
		return err
	}
	confirmation, err := ReadPassword("Confirm password: ")
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(password, confirmation) {
		return fmt.Errorf("passwords do not match")
	}
	defer Shred(password)
	defer Shred(confirmation)
	ct, err := EncryptCiphertext(rawPt, password)
	if err != nil {
		return err
	}
	rawCt, err := EncodeCiphertext(ct)
	if err != nil {
		return err
	}
	shares, err := SplitShares(rawCt, count, threshold)
	if err != nil {
		return err
	}
	return WriteShares(shares, inputPath)
}

func RunCombine(inputPaths []string, outputDir string) error {
	shares, err := ReadShares(inputPaths)
	if err != nil {
		return err
	}
	rawCt, err := CombineShares(shares)
	if err != nil {
		return err
	}
	ct, err := DecodeCiphertext(rawCt)
	if err != nil {
		return err
	}
	password, err := ReadPassword("Password: ")
	if err != nil {
		return err
	}
	defer Shred(password)
	rawPt, err := DecryptCiphertext(ct, password)
	if err != nil {
		return err
	}
	pt, err := DecodePlaintext(rawPt)
	if err != nil {
		return err
	}
	return WritePlaintext(pt, outputDir)

}
