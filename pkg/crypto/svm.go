package crypto

import (
	"io/ioutil"
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
		log.Debug("Error reading svm file: ", svmFile, err)
	}

	if strings.Trim(string(svm), "\n") == "1" {
		log.Debug("It is a VM with SVM/PEF support")
		return true
	}
	log.Debug("It is not an SVM")
	return false
}
