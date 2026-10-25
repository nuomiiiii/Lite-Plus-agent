package relocate

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf16"
)

func serviceFromCgroup(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		idx := strings.LastIndex(line, "/")
		if idx < 0 {
			continue
		}
		name := line[idx+1:]
		if cut := strings.IndexByte(name, '.'); cut > 0 && strings.HasPrefix(name[cut:], ".service") {
			return name[:cut]
		}
	}
	return ""
}

func withDisableTHP(envs []string) []string {
	out := make([]string, 0, len(envs)+1)
	found := false
	for _, env := range envs {
		if strings.HasPrefix(env, "GODEBUG=") {
			found = true
			if !strings.Contains(env, "disablethp=") {
				env = env + ",disablethp=1"
			}
		}
		out = append(out, env)
	}
	if !found {
		out = append(out, "GODEBUG=disablethp=1")
	}
	return out
}

func quoteUnitArg(value string) string {
	if value == "" || strings.ContainsAny(value, " \t\"'\\") {
		return strconv.Quote(value)
	}
	return value
}

func systemdUnit(next spec) string {
	var b strings.Builder
	b.WriteString("[Unit]\nDescription=Lite-Plus Agent Service\nAfter=network.target\n\n[Service]\nType=simple\n")
	b.WriteString("ExecStart=" + quoteUnitArg(next.Binary))
	for _, arg := range next.Args {
		b.WriteString(" " + quoteUnitArg(arg))
	}
	b.WriteString("\nWorkingDirectory=" + next.WorkDir + "\nRestart=always\nUser=root\n")
	for _, env := range withDisableTHP(next.Environment) {
		b.WriteString("Environment=" + quoteUnitArg(env) + "\n")
	}
	for _, file := range next.EnvironmentFiles {
		b.WriteString("EnvironmentFile=" + file + "\n")
	}
	b.WriteString("\n[Install]\nWantedBy=multi-user.target\n")
	return b.String()
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func lookPath(name string) string {
	path, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	return path
}

func nssmPath(dir string) string {
	if path := lookPath("nssm"); path != "" {
		return path
	}
	candidates := []string{filepath.Join(dir, "nssm.exe")}
	if pf := currentProgramFiles(); pf != "" {
		candidates = append(candidates,
			filepath.Join(pf, "Lite", "nssm.exe"),
			filepath.Join(pf, "Komari", "nssm.exe"),
		)
	}
	for _, candidate := range candidates {
		if candidate != "" && filepath.Base(candidate) == "nssm.exe" && fileExists(candidate) {
			return candidate
		}
	}
	return "nssm"
}

func decodeNssmOutput(raw []byte) string {
	if len(raw) >= 4 && raw[1] == 0 {
		if len(raw)%2 == 1 {
			raw = append(raw, 0)
		}
		n := len(raw) / 2
		u := make([]uint16, n)
		for i := 0; i < n; i++ {
			u[i] = binary.LittleEndian.Uint16(raw[i*2 : i*2+2])
		}
		return strings.TrimSpace(strings.Trim(string(utf16.Decode(u)), "\x00"))
	}
	return strings.TrimSpace(string(bytes.TrimRight(raw, "\x00")))
}
