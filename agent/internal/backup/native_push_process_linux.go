//go:build linux

package backup

import (
	"errors"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// The helper can spawn qemu-img while inspecting or restoring local files.
// Cancellation signals those owned children as well as Python; the attempt and
// output remain uncertain because a child in uninterruptible I/O may not exit
// immediately. The libvirt/QEMU domain job runs outside this process group;
// this never sends a generic domain-job abort or touches another client.
func configureNativeHelperProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
}

// Observe Python's exit without reaping it. Its PID therefore cannot be
// recycled while we signal the process group, including an owned qemu-img
// child left behind by an abrupt Python exit. Cmd.Wait then reaps Python and
// finishes the standard output-copy and WaitDelay handling.
func runNativeHelperCommand(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	pid := cmd.Process.Pid
	var info unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			_ = syscall.Kill(-pid, syscall.SIGKILL)
			return errors.Join(err, cmd.Wait())
		}
		break
	}
	killErr := syscall.Kill(-pid, syscall.SIGKILL)
	if errors.Is(killErr, syscall.ESRCH) {
		killErr = nil
	}
	return errors.Join(killErr, cmd.Wait())
}
