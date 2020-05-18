package crypto

import (
	"crypto/aes"
	"crypto/cipher"

	log "github.com/sirupsen/logrus"
)

const (
	rakshSecretsVMTEEDir = "/run/raksh/secrets"
	configMapKeyFileName = "configMapKey"
	imageKeyFileName     = "imageKey"
	nonceFileName        = "nonce"
)

//Returns true if VM TEE (SEV/PEF/MKTME)
func IsVMTEE() bool {
	log.Info("Check if running in VM TEE")
	if isSVM() == true {
		log.Info("Running in VM TEE")
		return true
	}
	//ToDo support for SEV and MKTME
	return false
}

//Get Secrets from VM TEE
func PopulateSecretsForVMTEE() error {
	log.Info("Check if SVM")

	if isSVM() == true {
		err := populateRakshSecretsForSVM()
		return err
	}

	//Add user secrets
	return nil
}

// DecryptConfigMap decrypts the config map
func DecryptConfigMap(data []byte, symmKey []byte, nonce []byte) ([]byte, error) {
	log.Info("Decrypt configMap")

	block, err := aes.NewCipher(symmKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintextBytes, err := aesgcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, err
	}

	return plaintextBytes, nil

}
