package crypto

import (
	"bytes"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	svmFile = "/sys/devices/system/cpu/svm"
)

//Returns true if SVM/PEF
func isSVM() bool {
	svm, err := ioutil.ReadFile(svmFile)
	if err != nil {
		log.Error("Error reading svm file: ", svmFile, err)
		return false
	}

	if strings.Trim(string(svm), "\n") == "1" {
		log.Info("It is a VM with SVM/PEF support")
		return true
	}
	log.Info("It is not an SVM")
	return false
}

//Populate secrets by calling esmb-get-file which will retrieve the
//embedded secret using ultravisor
func populateRakshSecretsForSVM() error {

	log.Debug("Populating secrets for SVM/PEF")
	err := os.MkdirAll(rakshSecretVMTEEMountPoint, os.ModeDir)
	if err != nil {
		log.Error("Unable to create directory for storing SVM/PEF secrets ", err)
		return err
	}
	configMapKeyFile := filepath.Join(rakshSecretVMTEEMountPoint, configMapKeyFileName)
	imageKeyFile := filepath.Join(rakshSecretVMTEEMountPoint, imageKeyFileName)
	nonceFile := filepath.Join(rakshSecretVMTEEMountPoint, nonceFileName)

	err = populateKeyFileforSVM(configMapKeyFile)
	if err != nil {
		return err
	}
	err = populateKeyFileforSVM(imageKeyFile)
	if err != nil {
		return err
	}
	err = populateKeyFileforSVM(nonceFile)
	if err != nil {
		return err
	}

	return nil
}

//Retrieve the secrets from SVM and write to the file
func populateKeyFileforSVM(fileName string) error {

	log.Debug("Populate the Key Files for SVM/PEF")
	_, err := os.Stat(fileName)
	if err == nil {
		log.Info("Secrets File exists for: ", fileName)
		return nil
	}
	//Retrieve imageKey
	filePtr, err := os.Create(fileName)
	if err != nil {
		log.Errorf("Unable to create file - ", fileName)
		return err
	}
	defer filePtr.Close()
	err = retrieveSecretsFilefromUltravisor(fileName, filePtr)
	if err != nil {
		log.Errorf("Error executing esmb-get-file for   ", fileName, err)
		return err
	}
	return nil
}

//Retrieve secrets file from SVM - ultravisor
func retrieveSecretsFilefromUltravisor(fileName string, outFile *os.File) error {

	log.Info("Retrieve the secrets from Ultravisor")
	var stderr bytes.Buffer

	cmd := exec.Command("esmb-get-file", "-f", fileName)
	//Note: NewLine gets added to Stdout. Buffer has an extra \n char
	cmd.Stdout = outFile
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		log.Errorf("Error executing esmb-get-file for configMapKey ", err, stderr.String())
		return err
	}
	return nil
}
