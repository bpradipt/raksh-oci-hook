package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/sirupsen/logrus"

	runSpec "github.com/opencontainers/runtime-spec/specs-go"
)

const (

	//Raksh Mount Points
	rakshMountPoint           = "/etc/raksh"
	rakshSecretMountPoint     = rakshMountPoint + "/secrets"
	rakshUserSecretMountPoint = rakshMountPoint + "/secrets/user"
	rakshEncConfigMapPath     = rakshMountPoint + "/spec"

	//Raksh secrets
	configMapKeyFileName = "configMapKey"
	imageKeyFileName     = "imageKey"
	nonceFileName        = "nonce"

	//Raksh properties
	rakshProperties = "properties"

	//VM TEE mount points (in-memory)
	rakshVMTEEMountPoint           = "/run/raksh"
	rakshSecretVMTEEMountPoint     = rakshVMTEEMountPoint + "/secrets"
	rakshUserSecretVMTEEMountPoint = rakshVMTEEMountPoint + "/secrets/user"
)

var (
	// version is the version string of the hook. Set at build time.
	log     = logrus.New()
	version = "0.0.1"
)

func init() {

	log.Out = os.Stdout

	dname, err := ioutil.TempDir("", "hooklog")
	fname := filepath.Join(dname, "hook.log")
	file, err := os.OpenFile(fname, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.Infof("Log file: %s", fname)
		log.Out = file
	} else {
		log.Info("Failed to log to file, using default stderr")
	}

}

func main() {

	log.Info("Started Raksh OCI hook version %s", version)

	start := flag.Bool("s", true, "Start the hook")
	printVersion := flag.Bool("version", false, "Print the hook's version")
	flag.Parse()

	if *printVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	if *start {
		log.Info("Starting Raksh OCI pre-start hook")
		if err := startRakshHook(); err != nil {
			//log.Fatal(err)
			log.Info(err)
			return
		}
	}
}

// Modify the Raksh secrets mount-point
func startRakshHook() error {
	//Hook receives container State in Stdin
	//https://github.com/opencontainers/runtime-spec/blob/master/config.md#posix-platform-hooks
	//https://github.com/opencontainers/runtime-spec/blob/master/runtime.md#state
	var s runSpec.State
	reader := bufio.NewReader(os.Stdin)
	decoder := json.NewDecoder(reader)
	err := decoder.Decode(&s)
	if err != nil {
		return err
	}

	//log spec to file
	log.Debugf("spec.State is %v", s)

	bundlePath := s.Bundle
	containerPid := s.Pid

	//Get source mount path for Raksh secrets
	rakshSecretSrcMountPath, err := getMountSrcFromConfigJson(bundlePath, rakshSecretMountPoint)
	if (rakshSecretSrcMountPath == "") || (err != nil) {
		log.Errorf("getting source mount path for %s returned %s", rakshSecretMountPoint, err)
		return err
	}
	log.Infof("Source mount path for Raksh secret is %s", rakshSecretSrcMountPath)

	//Get source mount path for Raksh spec (/etc/raksh/spec)
	rakshEncConfigMapMountPath, err := getMountSrcFromConfigJson(bundlePath, rakshEncConfigMapPath)
	if (rakshEncConfigMapMountPath == "") || (err != nil) {
		log.Errorf("getting source mount path for %s returned %s", rakshEncConfigMapPath, err)
		return err
	}
	log.Infof("Source mount path for Raksh encrypted config Map is %s", rakshEncConfigMapMountPath)

	//Read the Raksh secrets
	// /etc/raksh/secrets/{configMapKey, nonce, imageKey}
	configMapKey, nonce, imageKey, err := readRakshSecrets(rakshSecretSrcMountPath)
	if err != nil {
		log.Errorf("unable to read Raksh secret data %s", err)
		return err
	}
	log.Debugf("Raksh encrypted secrets %v, %v, %v", configMapKey, nonce, imageKey)

	//Read the encrypted configMap - properties
	// /etc/raksh/secrets/spec/properties
	encConfigMapFile := filepath.Join(rakshEncConfigMapMountPath, rakshProperties)
	encConfigMap, err := readSecretFile(encConfigMapFile)
	if err != nil {
		log.Errorf("Unable to read encConfigMap: %s", err)
		return err
	}

	log.Debugf("encrypted configMap %v", encConfigMap)

	scConfig, err := readEncryptedConfigmap(encConfigMap, configMapKey, nonce)
	if err != nil {
		log.Errorf("readEncryptedConfigmap errored out: %s", err)
		return err
	}

	log.Debugf("decrypted configMap %v", scConfig)

	err = modifyRakshBindMount(containerPid, bundlePath)
	if err != nil {
		log.Infof("Error modifying the Raksh mount point", err)
		return err
	}

	return nil
}

//Get source path of bind mount
func getMountSrcFromConfigJson(configJsonDir string, destMountPath string) (string, error) {

	var srcMountPath string
	//Take out the config.json from the bundle and edit the mount points
	configJsonPath := filepath.Join(configJsonDir, "config.json")

	log.Infof("Config.json location: %s", configJsonPath)
	//Read the JSON
	var config configs.Config
	jsonData, err := ioutil.ReadFile(configJsonPath)
	if err != nil {
		log.Errorf("unable to read config.json %s", err)
		return "", err
	}
	err = json.Unmarshal(jsonData, &config)
	if err != nil {
		log.Errorf("unable to unmarshal config.json %s", err)
		return "", err
	}
	for _, m := range config.Mounts {
		log.Infof("src: %s  ==  dest: %s", m.Source, m.Destination)
		//Check if dest matches destMountPath
		if strings.Contains(m.Destination, destMountPath) == true {
			srcMountPath = m.Source
			break
		}
	}

	log.Infof("mount src from config.json: %s", srcMountPath)

	return srcMountPath, nil

}

func modifyRakshBindMount(pid int, bundlePath string) error {

	log.Infof("modifying bind mount for process %d", pid)

	// Enter_namespaces_of_process(containerPid)
	// - mnt (/proc/containerPid/ns/mnt)
	// - pid (/proc/containerPid/ns/pid)
	// list mount points

	args := []string{"-t", strconv.Itoa(pid), "-m", "-p", "mount"}
	cmd := exec.Command("nsenter", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Infof("Error in executing mount ", err)
		log.Infof("out ", string(out))
		return err
	}

	log.Debugf("Existing mount list inside the container : ", string(out))

	//Unmount raksh properties
	mntDest := filepath.Join(bundlePath, "rootfs", rakshEncConfigMapPath)
	args = []string{"-t", strconv.Itoa(pid), "-m", "-p", "umount", mntDest}
	cmd = exec.Command("nsenter", args...)
	out, err = cmd.CombinedOutput()
	if err != nil {
		log.Infof("Error in executing umount for %s", mntDest, err)
		log.Infof("out ", string(out))
		return err
	}

	//Unmount raksh secrets
	mntDest = filepath.Join(bundlePath, "rootfs", rakshSecretMountPoint)
	args = []string{"-t", strconv.Itoa(pid), "-m", "-p", "umount", mntDest}
	cmd = exec.Command("nsenter", args...)
	out, err = cmd.CombinedOutput()
	if err != nil {
		log.Infof("Error in executing umount for %s ", mntDest, err)
		log.Infof("out ", string(out))
		return err
	}

	log.Infof("Modifying bind mount complete")
	return nil

}
