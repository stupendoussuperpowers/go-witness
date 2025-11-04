package witnessd

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/in-toto/go-witness/log"
	"golang.org/x/sys/unix"
)

const PIDFILE = "/var/witnessd.pid"
const WITNESSD_PATH = "witnessd"
const SOCKET_PATH = "/var/witnessd.sock"

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

func GetLogs(pid int) ([]string, error) {
	conn, err := net.Dial("unix", SOCKET_PATH)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte(fmt.Sprintf("GET %d\n", pid)))
	if err != nil {
		return nil, err
	}

	var output []string

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "END") {
			break
		}
		if strings.HasPrefix(line, "ERROR") {
			return nil, fmt.Errorf("witnessd error: %s", line)
		}

		output = append(output, line)
	}

	return output, nil
}
