//go:build !linux

package backup

import "os/exec"

// The native runner is Linux-only; other builds retain CommandContext's
// default direct-child cancellation behavior.
func configureNativeHelperProcess(_ *exec.Cmd) {}

func runNativeHelperCommand(cmd *exec.Cmd) error { return cmd.Run() }
