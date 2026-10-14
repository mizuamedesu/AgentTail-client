// Package skills installs public CLI guidance, never credentials or grants.
package skills

import (
	_ "embed"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

//go:embed agenttail-vpn/SKILL.md
var content []byte

type Result struct {
	Agent  string `json:"agent"`
	Path   string `json:"path"`
	Status string `json:"status"`
}

func Install() ([]Result, error) {
	// The unprivileged bootstrap invokes this after the privileged file install.
	// Never follow a sudo user's home tree while holding root privileges.
	if runtime.GOOS != "windows" && os.Geteuid() == 0 && os.Getenv("SUDO_UID") != "" && os.Getenv("SUDO_UID") != "0" {
		return nil, errors.New("run agenttail skills install as your normal user, without sudo")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return installAt(home, func(name string) bool { _, err := exec.LookPath(name); return err == nil })
}
func installAt(home string, detected func(string) bool) ([]Result, error) {
	var result []Result
	for _, a := range []struct{ name, config, folder string }{{"codex", ".codex", ".agents"}, {"claude", ".claude", ".claude"}} {
		_, configErr := os.Stat(filepath.Join(home, a.config))
		if !detected(a.name) && configErr != nil {
			result = append(result, Result{Agent: a.name, Status: "not_detected"})
			continue
		}
		path := filepath.Join(home, a.folder, "skills", "agenttail-vpn", "SKILL.md")
		// Refuse existing symlink components. A skill is installed under the
		// invoking user's authority, so it cannot write into another user's home.
		p := home
		for _, part := range []string{a.folder, "skills", "agenttail-vpn"} {
			p = filepath.Join(p, part)
			i, err := os.Lstat(p)
			if err == nil && (!i.IsDir() || i.Mode()&os.ModeSymlink != 0) {
				return result, errors.New("skill directory must not contain symbolic links")
			}
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return result, err
			}
			if errors.Is(err, os.ErrNotExist) {
				if err = os.Mkdir(p, 0755); err != nil {
					return result, err
				}
			}
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if errors.Is(err, os.ErrExist) {
			result = append(result, Result{Agent: a.name, Path: path, Status: "preserved_existing"})
			continue
		}
		if err != nil {
			return result, err
		}
		_, err = f.Write(content)
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			os.Remove(path)
			if err != nil {
				return result, err
			}
			return result, closeErr
		}
		result = append(result, Result{Agent: a.name, Path: path, Status: "installed"})
	}
	return result, nil
}
