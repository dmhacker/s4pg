package s4pg

import (
	"fmt"
	"path/filepath"
	"reflect"
)

func SplitPlaintextFile(inputPath string, count int, threshold int) error {
    // Read the plaintext & any metadata from the input path
	pt, err := ReadPlaintext(inputPath)
	if err != nil {
		return err
	}
	ptBytes, err := EncodePlaintext(pt)
	if err != nil {
		return err
	}
    // Read the user's password from the command line
    // The password can be 0 bytes (the enclave is nil in that case)
	passwordEnclave, err := ReadPassword("Password: ")
	if err != nil {
		return err
	}
	var passwordBytes []byte
	if passwordEnclave == nil {
		passwordBytes = []byte{}
	} else {
		password, err := passwordEnclave.Open()
		if err != nil {
			return err
		}
		defer password.Destroy()
		passwordBytes = password.Bytes()
	}
    // User enters password twice to confirm
	confirmEnclave, err := ReadPassword("Confirm password: ")
	if err != nil {
		return err
	}
	var confirmBytes []byte
	if confirmEnclave == nil {
		confirmBytes = []byte{}
	} else {
		confirm, err := confirmEnclave.Open()
		if err != nil {
			return err
		}
		defer confirm.Destroy()
		confirmBytes = confirm.Bytes()
	}
	if !reflect.DeepEqual(passwordBytes, confirmBytes) {
		return fmt.Errorf("passwords do not match")
	}
    // Encrypt plaintext using a key derived from the password
	ct, err := EncryptCiphertext(ptBytes, passwordBytes)
	if err != nil {
		return err
	}
	ctBytes, err := EncodeCiphertext(ct)
	if err != nil {
		return err
	}
    // Split resulting ciphertext into multiple shares
	shares, err := SplitShares(ctBytes, count, threshold)
	if err != nil {
		return err
	}
    // Write shares to user's current directory
	return WriteShares(shares, filepath.Join(".", filepath.Base(inputPath)))
}

func CombineShareFiles(inputPaths []string) error {
    // Read shares from input paths
	shares, err := ReadShares(inputPaths)
	if err != nil {
		return err
	}
    // Combine shares into password-protected ciphertext
	ctBytes, err := CombineShares(shares)
	if err != nil {
		return err
	}
	ct, err := DecodeCiphertext(ctBytes)
	if err != nil {
		return err
	}
    // Read the user's password from the command line
    // The password can be 0 bytes (the enclave is nil in that case)
	passwordEnclave, err := ReadPassword("Password: ")
	if err != nil {
		return err
	}
	var passwordBytes []byte
	if passwordEnclave == nil {
		passwordBytes = []byte{}
	} else {
		password, err := passwordEnclave.Open()
		if err != nil {
			return err
		}
		defer password.Destroy()
		passwordBytes = password.Bytes()
	}
    // Decrypt the ciphertext into the original plaintext
	ptBytes, err := DecryptCiphertext(ct, passwordBytes)
	if err != nil {
		return err
	}
	pt, err := DecodePlaintext(ptBytes)
	if err != nil {
		return err
	}
    // Write the plaintext to the user's current directory
	return WritePlaintext(pt, ".")
}
