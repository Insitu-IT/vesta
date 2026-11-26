//go:build linux

package backup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestNativeHelperCancellationStopsOwnedChild(t *testing.T) {
	previous := nativePushHelper
	nativePushHelper = `import json, os, subprocess, sys, time
request = json.load(sys.stdin)["request"]
child = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(30)"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
with open(request["pid_file"], "w", encoding="ascii") as marker:
    marker.write(str(child.pid))
    marker.flush()
    os.fsync(marker.fileno())
while True:
    time.sleep(1)
`
	defer func() { nativePushHelper = previous }()

	pidFile := filepath.Join(t.TempDir(), "child.pid")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		var result struct{}
		done <- runNativeHelper(ctx, "backup", map[string]string{"pid_file": pidFile}, &result)
	}()

	var pid int
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		body, err := os.ReadFile(pidFile)
		if err == nil && len(body) > 0 {
			pid, err = strconv.Atoi(string(body))
			if err != nil || pid <= 0 {
				t.Fatalf("invalid owned child PID: %q", body)
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pid == 0 {
		t.Fatal("native helper did not start its owned child")
	}
	defer syscall.Kill(pid, syscall.SIGKILL) // Exact test-owned child only.
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNativeUncertain) {
			t.Fatalf("cancellation must retain uncertain custody: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("native helper did not stop after cancellation")
	}

	waitNativeOwnedChildStopped(t, pid)
}

func TestNativeHelperUnexpectedExitStopsOwnedChild(t *testing.T) {
	previous := nativePushHelper
	nativePushHelper = `import json, os, subprocess, sys
request = json.load(sys.stdin)["request"]
child = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(30)"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
with open(request["pid_file"], "w", encoding="ascii") as marker:
    marker.write(str(child.pid))
    marker.flush()
    os.fsync(marker.fileno())
os._exit(17)
`
	defer func() { nativePushHelper = previous }()

	pidFile := filepath.Join(t.TempDir(), "child.pid")
	var result struct{}
	err := runNativeHelper(context.Background(), "backup", map[string]string{"pid_file": pidFile}, &result)
	if !errors.Is(err, ErrNativeUncertain) {
		t.Fatalf("abrupt helper exit must retain uncertain custody: %v", err)
	}
	body, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(body))
	if err != nil || pid <= 0 {
		t.Fatalf("invalid owned child PID: %q", body)
	}
	defer syscall.Kill(pid, syscall.SIGKILL) // Exact test-owned child only.
	waitNativeOwnedChildStopped(t, pid)
}

func TestNativeHelperSuccessfulExitStillReturnsResult(t *testing.T) {
	previous := nativePushHelper
	nativePushHelper = `import json, sys
json.load(sys.stdin)
print(json.dumps({"ok": True}))
`
	defer func() { nativePushHelper = previous }()
	var result struct {
		OK bool `json:"ok"`
	}
	if err := runNativeHelper(context.Background(), "backup", struct{}{}, &result); err != nil || !result.OK {
		t.Fatalf("successful helper result lost: result=%+v err=%v", result, err)
	}
}

func waitNativeOwnedChildStopped(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		body, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		end := strings.LastIndexByte(string(body), ')')
		if end < 0 {
			t.Fatalf("invalid child process state: %q", body)
		}
		fields := strings.Fields(string(body[end+1:]))
		if len(fields) > 0 && fields[0] == "Z" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("owned helper child remained running after helper exit")
}
