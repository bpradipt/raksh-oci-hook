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

	"github.com/sirupsen/logrus"

	runSpec "github.com/opencontainers/runtime-spec/specs-go"
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

	//Basic skeleton

	err = modifyRakshBindMount(containerPid, bundlePath)
	if err != nil {
		log.Infof("Error modifying the Raksh mount point", err)
		return err
	}

	return nil
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

	log.Infof("Modifying bind mount complete")
	return nil

}
