package agentutils

import (
	"os/exec"
	"strings"
)

func RunCommand(name string, arg ...string) (string, string, error) {
	cmd := exec.Command(name, arg...) // #nosec G204 - This function is expected to run any supplied command
	var stdout strings.Builder
	var stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	return stdout.String(), stderr.String(), err
}
