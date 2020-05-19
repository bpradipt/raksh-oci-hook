package main

import (
	b64 "encoding/base64"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/ghodss/yaml"
	"github.com/raksh-oci-hook/pkg/crypto"
)

type requests struct {
	CPU    string `yaml:"cpu"`
	Memory string `yaml:"memory"`
}
type resources struct {
	Requests requests `yaml:"requests"`
}
type env struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}
type ports struct {
	ContainerPort int `yaml:"containerPort"`
}
type containers struct {
	Name      string    `yaml:"name"`
	Image     string    `yaml:"image"`
	Resources resources `yaml:"resources"`
	Args      []string  `yaml:"args"`
	Env       []env     `yaml:"env"`
	Cwd       string    `yaml:"cwd"`
	Ports     []ports   `yaml:"ports"`
}
type spec struct {
	Containers []containers `yaml:"containers"`
}
type scConfig struct {
	Spec spec `yaml:"spec"`
}

//Read encrypted ConfigMap containing Raksh properties
func readEncryptedConfigmap(encryptedYamlContainerSpec []byte, configMapKey []byte, nonce []byte) (*scConfig, error) {

	var scConfig scConfig

	log.Infof("Reading encrypted configmap")

	decryptedConfigMap, err := crypto.DecryptConfigMap(encryptedYamlContainerSpec, configMapKey, nonce)
	if err != nil {
		log.Errorf("Error in decrypting configMap %s", err)
		return nil, err
	}
	log.Debugf("Decrypted configmap %v", decryptedConfigMap)

	err = persistDecryptedConfigMap(decryptedConfigMap)
	if err != nil {
		log.Errorf("Error when persisting decrypted configmap %s", err)
		return nil, err
	}

	err = yaml.Unmarshal(decryptedConfigMap, &scConfig)
	if err != nil {
		log.Errorf("Error unmarshalling yaml %s", err)
		return nil, err
	}

	return &scConfig, err

}

//Read the Raksh secrets
func readRakshUserSecrets(srcPath string, decKey []byte, nonce []byte) (userSecrets map[string][]byte, err error) {
	log.Infof("Read Raksh User secrets")
	//read all key value pairs under srcPath
	files, err := ioutil.ReadDir(srcPath)
	if err != nil {
		log.Errorf("Unable to read the secrets %s", err)
		return nil, err
	}
	userSecrets = make(map[string][]byte)
	for _, file := range files {
		log.Debugf("User secret key %s", file.Name())
		userSecrets[file.Name()] = []byte{}
                keyPath := filepath.Join(srcPath, file.Name())
		value, err := readSecretFile(keyPath)
		if err != nil {
			log.Errorf("Reading the value for %s resulted in error %s", file.Name(), err)
			continue
		}
		//Decrypt the value. Use the master secret from Raksh secrets configMapKey and nonce
		decValue, err := crypto.DecryptConfigMap(value, decKey, nonce)
		if err != nil {
			log.Errorf("Error in decrypting user secret key %s", err)
			continue
		}
		userSecrets[file.Name()] = decValue
                persistDecryptedUserSecrets(file.Name(), decValue)
		log.Debugf("User secret value %s", string(decValue))
	}
	log.Debugf("User Secrets map: %v", userSecrets)
	return userSecrets, nil

}

//Read the Raksh secrets
func readRakshSecrets(srcPath string) (configMapKey []byte, nonce []byte, imageKey []byte, err error) {

	var configMapKeyFile, nonceFile, imageKeyFile string

	log.Infof("Read Raksh secrets")

	//Decrypt the secret data - local/remote attestation etc
	if crypto.IsVMTEE() == true {
		//VM TEE
		err = crypto.PopulateSecretsForVMTEE()
		if err != nil {
			log.Errorf("Error populating secrets for TEE")
			return nil, nil, nil, err
		}
		configMapKeyFile = filepath.Join(rakshSecretVMTEEMountPoint, configMapKeyFileName)
		imageKeyFile = filepath.Join(rakshSecretVMTEEMountPoint, imageKeyFileName)
		nonceFile = filepath.Join(rakshSecretVMTEEMountPoint, nonceFileName)
		log.Debug("Found secrets at: ", rakshSecretVMTEEMountPoint)
	} else {
		//non VM TEE case
		configMapKeyFile = filepath.Join(srcPath, configMapKeyFileName)
		nonceFile = filepath.Join(srcPath, nonceFileName)
		imageKeyFile = filepath.Join(srcPath, imageKeyFileName)
		log.Debug("Found secrets at: ", srcPath)
	}

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

//Persist the decrypted configMap in memory
func persistDecryptedConfigMap(decryptedConfigMap []byte) error {

	err := os.MkdirAll(rakshSecretVMTEEMountPoint, os.ModeDir)
	if err != nil {
		log.Debug("Unable to create directory for storing decrypted configMap")
		return err
	}
	decryptCMFile := filepath.Join(rakshSecretVMTEEMountPoint, "decryptedConfigMap")
	log.Debug("Write decrypted configmap into: ", decryptCMFile)
	err = ioutil.WriteFile(decryptCMFile, decryptedConfigMap, 0644)
	return err
}

//Persist the decrypted user secrets in memory
func persistDecryptedUserSecrets(fileName string, plaintextData []byte) error {

	err := os.MkdirAll(rakshUserSecretVMTEEMountPoint, os.ModeDir)
	if err != nil {
		log.Debug("Unable to create directory for storing decrypted user secrets")
		return err
	}
	decryptKeyFile := filepath.Join(rakshUserSecretVMTEEMountPoint, fileName)
	log.Info("Write decrypted user secret key into: ", decryptKeyFile)
	err = ioutil.WriteFile(decryptKeyFile, plaintextData, 0644)
	return err
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
