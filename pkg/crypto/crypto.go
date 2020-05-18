package crypto

import (
	"crypto/aes"
	"crypto/cipher"

	log "github.com/sirupsen/logrus"
)

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
