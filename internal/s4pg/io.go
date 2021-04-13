package s4pg

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
)

func ReadPlaintext(fpath string) (Plaintext, error) {
	var pt Plaintext
	content, err := ioutil.ReadFile(fpath)
	pt.Content = content
	if err != nil {
		return pt, err
	}
	pt.Filename = filepath.Base(fpath)
	if err != nil {
		return pt, err
	}
	return pt, nil
}

func ReadShares(fpaths []string) ([]Share, error) {
	rawShares := make([][]byte, len(fpaths))
	for i, fpath := range fpaths {
		rawShare, err := ioutil.ReadFile(fpath)
		if err != nil {
			return nil, err
		}
		rawShares[i] = rawShare
	}
	return DecodeShares(rawShares)
}

func WritePlaintext(pt Plaintext, fdir string) error {
	fpath := filepath.Join(fdir, pt.Filename)
	if _, err := os.Stat(fpath); os.IsExist(err) {
		return fmt.Errorf("'%s' already exists; will not overwrite", fpath)
	}
	err := ioutil.WriteFile(fpath, pt.Content, 0644)
	if err != nil {
		return err
	}
	fmt.Printf("Recreated original file: %v\n", fpath)
	return nil
}

func WriteShares(shares []Share, fpath string) error {
	rawShares, err := EncodeShares(shares)
	if err != nil {
		return err
	}
	spaths := make([]string, len(rawShares))
	for i, rawShare := range rawShares {
		spaths[i] = fpath + "." + strconv.Itoa(i+1) + ".s4pg"
		if _, err := os.Stat(spaths[i]); os.IsExist(err) {
			return fmt.Errorf("'%s' already exists; will not overwrite", spaths[i])
		}
		err = ioutil.WriteFile(spaths[i], rawShare, 0644)
		if err != nil {
			return err
		}
	}
	fmt.Printf("Created share files: %v\n", spaths)
	return nil
}
