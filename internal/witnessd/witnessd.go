package witnessd

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/in-toto/go-witness/log"
	"golang.org/x/sys/unix"
)

const PIDFILE = "/var/witnessd.pid"
const WITNESSD_PATH = "witnessd"

func isRunning() bool {
	data, err := os.ReadFile(PIDFILE)
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return false
	}
	err = syscall.Kill(pid, 0)
	return err == nil
}

func Launch() error {
	if isRunning() {
		return nil
	}

	outputFile, err := os.OpenFile("/var/log/witnessd.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Errorf("Error creating witnessd og file:%v", err)
		return err
	}
	defer outputFile.Close()

	cmd := exec.Command(WITNESSD_PATH)
	cmd.Stdout = outputFile
	cmd.Stderr = outputFile
	cmd.Stdin = nil

	cmd.SysProcAttr = &unix.SysProcAttr{
		Setsid: true,
	}

	if err := cmd.Start(); err != nil {
		log.Infof("Failed to start witnessd: %v", err)
		return err
	}

	time.Sleep(time.Second)

	return nil
}
