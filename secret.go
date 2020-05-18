package main

import (
	b64 "encoding/base64"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
)

//Read the Raksh secrets
func readRakshSecrets(srcPath string) (configMapKey []byte, nonce []byte, imageKey []byte, err error) {

	var configMapKeyFile, nonceFile, imageKeyFile string

	log.Infof("Read Raksh secrets")

	configMapKeyFile = filepath.Join(srcPath, configMapKeyFileName)
	nonceFile = filepath.Join(srcPath, nonceFileName)
	imageKeyFile = filepath.Join(srcPath, imageKeyFileName)
	log.Debug("Found secrets at: ", srcPath)

	configMapKey, err = readSecretFile(configMapKeyFile)
	if err != nil {
		return nil, nil, nil, err
	}

	imageKey, err = readSecretFile(imageKeyFile)
	if err != nil {
		return nil, nil, nil, err
	}

	nonce, err = readSecretFile(nonceFile)
	if err != nil {
		return nil, nil, nil, err
	}

	return configMapKey, nonce, imageKey, nil
}

//Get the secrets from the relevant files
func readSecretFile(fileName string) ([]byte, error) {

	err := fileExists(fileName)
	if err != nil {
		log.Errorf("Error looking for %s", fileName)
		return nil, err
	}

	//The secrets are base64 encoded
	keyEnc, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Errorf("Could not read file %s: %s", fileName, err)
		return nil, err
	}

	keyDecoded, err := b64.StdEncoding.DecodeString(string(keyEnc))
	return keyDecoded, err
}

//Check if the given file exists
func fileExists(path string) error {

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return errors.New("File does not exist")
	} else if err != nil {
		return errors.New("File exists")
	}
	return nil
}
