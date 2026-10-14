// SPDX-License-Identifier: GPL-3.0-or-later

package service

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func testBusybox(t *testing.T) busyboxService {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root-owned service fixtures require root")
	}
	d := t.TempDir()
	return busyboxService{filepath.Join(d, "etc"), filepath.Join(d, "run"), filepath.Join(d, "init.d/S99agenttail")}
}
func TestBusyBoxHelper(t *testing.T) {
	if os.Getenv("AGENTTAIL_SERVICE_HELPER") != "1" {
		return
	}
	b := busyboxService{os.Getenv("TEST_CONFIG"), os.Getenv("TEST_RUNTIME"), os.Getenv("TEST_INIT")}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()
	var err error
	switch os.Getenv("TEST_ACTION") {
	case "start":
		err = b.start()
	case "stop":
		err = b.stop()
	default:
		err = b.supervise(ctx)
	}
	if err != nil {
		t.Fatal(err)
	}
}
func busyboxFixture(t *testing.T, b busyboxService, childScript string) (string, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if candidate := os.Getenv("AGENTTAIL_TEST_BINARY"); candidate != "" {
		exe = candidate
	}
	state := filepath.Join(filepath.Dir(b.configDir), "state with ' quote")
	if err = os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(filepath.Dir(b.configDir), "fixture-cli")
	t.Setenv("AGENTTAIL_SERVICE_HELPER", "1")
	t.Setenv("TEST_CONFIG", b.configDir)
	t.Setenv("TEST_RUNTIME", b.runtimeDir)
	t.Setenv("TEST_INIT", b.initPath)
	runner := ""
	if value := os.Getenv("AGENTTAIL_TEST_RUNNER"); value != "" {
		runner = shellQuote(value) + " "
	}
	helper := "exec " + runner + shellQuote(exe) + " -test.run=^TestBusyBoxHelper$ >" + shellQuote(filepath.Join(b.runtimeDir, "helper.log")) + " 2>&1\n"
	script := "#!/bin/sh\nif [ \"$3\" = service ]; then export TEST_ACTION=\"$4\"; " + helper + "fi\nif [ \"$4\" = supervise ]; then unset TEST_ACTION; " + helper + "fi\n" + childScript
	if err = os.WriteFile(fake, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	return fake, state
}

func TestBusyBoxLifecycleAndCrashRestart(t *testing.T) {
	b := testBusybox(t)
	fake, state := busyboxFixture(t, b, "printf '%s\\n' $$ > \"$2/child.pid\"\nexec /bin/sleep 300\n")
	defer b.uninstall()
	if err := b.install(fake, state); err != nil {
		log, _ := os.ReadFile(filepath.Join(b.runtimeDir, "supervisor.json"))
		var record busyboxPID
		_ = json.Unmarshal(log, &record)
		actual, stateErr := processStart(record.PID)
		t.Fatalf("%v (helper %s): record=%s actual=%s err=%v", err, fake, log, actual, stateErr)
	}
	status, err := b.inspect()
	if err != nil || !status.Installed || !status.Running {
		t.Fatalf("install: %+v %v", status, err)
	}
	pidBefore, err := os.ReadFile(filepath.Join(b.runtimeDir, "supervisor.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = b.start(); err != nil {
		t.Fatal(err)
	}
	pidAfter, _ := os.ReadFile(filepath.Join(b.runtimeDir, "supervisor.json"))
	if string(pidBefore) != string(pidAfter) {
		t.Fatal("duplicate supervisor started")
	}
	childPID := func() int {
		data, _ := os.ReadFile(filepath.Join(state, "child.pid"))
		pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
		return pid
	}
	until := func(f func() bool) {
		t.Helper()
		for end := time.Now().Add(20 * time.Second); time.Now().Before(end); {
			if f() {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("service transition timed out")
	}
	until(func() bool { return childPID() > 1 })
	child := childPID()
	if err = syscall.Kill(child, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	until(func() bool { return childPID() > 1 && childPID() != child })
	if err = b.stop(); err != nil {
		t.Fatal(err)
	}
	status, err = b.inspect()
	if err != nil || status.Running {
		t.Fatal("stop failed", err)
	}
	// Invoke the actual generated boot script with BusyBox ash (including a
	// state path containing spaces and a quote), then stop it the same way.
	busybox, err := exec.LookPath("busybox")
	if err != nil {
		t.Fatal("BusyBox is required for this service test")
	}
	for _, action := range []string{"start", "stop"} {
		output, err := exec.Command(busybox, "sh", b.initPath, action).CombinedOutput()
		if err != nil {
			t.Fatalf("boot %s: %v %s", action, err, output)
		}
		status, err = b.inspect()
		if err != nil || status.Running != (action == "start") {
			t.Fatal("boot script state", err)
		}
	}
	if err = b.uninstall(); err != nil {
		t.Fatal(err)
	}
	status, err = b.inspect()
	if err != nil || status.Installed || status.Running {
		t.Fatal("uninstall failed", err)
	}
	if _, err = os.Stat(b.initPath); !os.IsNotExist(err) {
		t.Fatal("boot script remains")
	}
}

func TestBusyBoxFailedAgentRetainsBoundedPrivateDiagnostics(t *testing.T) {
	b := testBusybox(t)
	fake, state := busyboxFixture(t, b, "printf '%06000d' 0 >&2\nprintf '\\nfixture startup failure\\n' >&2\nexit 7\n")
	defer b.uninstall()
	if err := b.install(fake, state); err != nil {
		t.Fatal(err)
	}
	var status Status
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		var err error
		status, err = b.inspect()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(status.LastFailure, "fixture startup failure") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !status.Running || !strings.Contains(status.LastFailure, "exit status 7") || !strings.Contains(status.LastFailure, "fixture startup failure") {
		t.Fatalf("lost child startup failure: %+v", status)
	}
	info, err := os.Stat(b.failurePath())
	if err != nil || info.Size() > maxFailureOutput+1 || info.Mode().Perm() != 0600 {
		t.Fatalf("unbounded or unprotected failure record: %v %v", info, err)
	}
	// Installation rollback removes the service but must leave its failure
	// reason available for the user to inspect.
	if err = b.uninstall(); err != nil {
		t.Fatal(err)
	}
	if failure, err := b.lastFailure(); err != nil || !strings.Contains(failure, "fixture startup failure") {
		t.Fatal("rollback lost diagnostics", failure, err)
	}
	if err = b.recordFailure("old failure"); err != nil {
		t.Fatal(err)
	}
	// The same managed path now stays up. Starting afresh clears stale errors.
	if err = os.WriteFile(fake, []byte(strings.ReplaceAll(string(mustRead(t, fake)), "exit 7", "exec /bin/sleep 300")), 0755); err != nil {
		t.Fatal(err)
	}
	if err = b.install(fake, state); err != nil {
		t.Fatal(err)
	}
	if failure, err := b.lastFailure(); err != nil || failure != "" {
		t.Fatal("fresh start retained an old failure", failure, err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func TestBusyBoxRefusesForeignScriptAndReusedPID(t *testing.T) {
	b := testBusybox(t)
	if err := b.prepare(); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(busyboxPID{os.Getpid(), "wrong-start-time"})
	if err := os.WriteFile(filepath.Join(b.runtimeDir, "supervisor.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := b.stop(); err != nil {
		t.Fatal(err)
	} // Must not signal this test process.
	if err := os.MkdirAll(filepath.Dir(b.initPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b.initPath, []byte("#!/bin/sh\n# another application\n"), 0755); err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	if err := b.install(exe, filepath.Join(filepath.Dir(b.configDir), "state")); err == nil {
		t.Fatal("foreign init script overwritten")
	}
}
