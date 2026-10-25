package relocate

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLooksLikeExistingInstallDetectsManagedLayouts(t *testing.T) {
	if !looksLikeExistingInstall("linux", "/opt/lite-plus-agent/Lite-Plus-agent", "", "", func(string) error { return os.ErrNotExist }) {
		t.Fatal("plus linux layout should look like an existing install")
	}
	if !looksLikeExistingInstall("linux", "/opt/lite-agent/Lite-agent", "", "", func(string) error { return os.ErrNotExist }) {
		t.Fatal("lite linux layout should look like an existing install")
	}
	if !looksLikeExistingInstall("linux", "/opt/komari/agent", "", "", func(string) error { return os.ErrNotExist }) {
		t.Fatal("legacy linux layout should look like an existing install")
	}
	if looksLikeExistingInstall("linux", "/tmp/custom/Lite-Plus-agent", "", "", func(string) error { return os.ErrNotExist }) {
		t.Fatal("custom path without sidecars should look like a new install")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "node.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if !looksLikeExistingInstall("linux", filepath.Join(dir, "Lite-Plus-agent"), "", "", statPath) {
		t.Fatal("sidecar node.json should look like an existing install")
	}
	if !looksLikePriorHostInstall("linux", filepath.Join(dir, "Lite-Plus-agent"), "", "", statPath) {
		t.Fatal("sidecar node.json should count as a host upgrade")
	}
	if !looksLikeExistingInstall("linux", "/tmp/x/Lite-Plus-agent", "", "", func(path string) error {
		if path == "/.komari-agent-container" {
			return nil
		}
		return os.ErrNotExist
	}) {
		t.Fatal("container marker should look like an existing install")
	}
	if looksLikePriorHostInstall("linux", "/opt/lite-plus-agent/Lite-Plus-agent", "", "", func(path string) error {
		if path == "/.lite-plus-agent-container" || path == "/.lite-agent-container" || path == "/.komari-agent-container" {
			return nil
		}
		return os.ErrNotExist
	}) {
		t.Fatal("container marker must not count as a host upgrade")
	}
	if looksLikePriorHostInstall("linux", "/opt/lite-plus-agent/Lite-Plus-agent", "", "", func(string) error { return os.ErrNotExist }) {
		t.Fatal("empty plus linux layout must not count as a host upgrade")
	}
	if !looksLikePriorHostInstall("linux", "/opt/komari/agent", "", "", func(string) error { return os.ErrNotExist }) {
		t.Fatal("legacy linux layout should count as a host upgrade")
	}
	if !looksLikePriorHostInstall("linux", "/opt/lite-agent/Lite-agent", "", "", func(string) error { return os.ErrNotExist }) {
		t.Fatal("lite linux layout should count as a host upgrade")
	}
	if !looksLikePriorHostInstall("linux", "/opt/lite-plus-agent/Lite-Plus-agent", "", "", func(path string) error {
		if filepath.Base(path) == "auto-discovery.json" {
			return nil
		}
		return os.ErrNotExist
	}) {
		t.Fatal("plus layout with auto-discovery.json should count as a host upgrade")
	}
}

func TestDetectPlanUsesPlusAgentProcessName(t *testing.T) {
	plan, ok := detectPlan("linux", "/opt/komari/agent", "", "")
	if !ok {
		t.Fatal("default linux komari layout should relocate")
	}
	if plan.To.BinaryName != "Lite-Plus-agent" {
		t.Fatalf("linux process name = %q, want Lite-Plus-agent", plan.To.BinaryName)
	}
	if plan.To.Dir != "/opt/lite-plus-agent" || plan.To.Service != "lite-plus-agent" {
		t.Fatalf("linux destination = %+v", plan.To)
	}

	plan, ok = detectPlan("linux", "/opt/lite-agent/Lite-agent", "", "")
	if !ok {
		t.Fatal("default linux lite layout should relocate to plus")
	}
	if plan.From.Service != "lite-agent" || plan.To.Service != "lite-plus-agent" {
		t.Fatalf("lite to plus = from %+v to %+v", plan.From, plan.To)
	}

	plan, ok = detectPlan("darwin", "/usr/local/komari/agent", "/Users/joey", "")
	if !ok {
		t.Fatal("default darwin layout should relocate")
	}
	if plan.To.BinaryName != "Lite-Plus-agent" {
		t.Fatalf("darwin process name = %q, want Lite-Plus-agent", plan.To.BinaryName)
	}
	if plan.To.Dir != "/usr/local/lite-plus-agent" {
		t.Fatalf("darwin destination dir = %q", plan.To.Dir)
	}

	plan, ok = detectPlan("darwin", "/Users/joey/.lite-agent/Lite-agent", "/Users/joey", "")
	if !ok {
		t.Fatal("darwin user lite layout should relocate")
	}
	wantUserDir := filepath.Join("/Users/joey", ".lite-plus-agent")
	if plan.To.Dir != wantUserDir {
		t.Fatalf("darwin user destination dir = %q, want %q", plan.To.Dir, wantUserDir)
	}

	if runtime.GOOS != "windows" {
		return
	}

	plan, ok = detectPlan("windows", `C:\Program Files\Komari\komari-agent.exe`, "", `C:\Program Files`)
	if !ok {
		t.Fatal("default windows komari layout should relocate")
	}
	if plan.To.BinaryName != "Lite-Plus-agent.exe" {
		t.Fatalf("windows process name = %q, want Lite-Plus-agent.exe", plan.To.BinaryName)
	}
	if plan.To.Dir != filepath.Join(`C:\Program Files`, "Lite-Plus") {
		t.Fatalf("windows destination dir = %q", plan.To.Dir)
	}

	plan, ok = detectPlan("windows", `C:\Program Files\Lite\Lite-agent.exe`, "", `C:\Program Files`)
	if !ok {
		t.Fatal("windows lite layout should relocate to plus")
	}
	if plan.To.Dir != filepath.Join(`C:\Program Files`, "Lite-Plus") {
		t.Fatalf("windows lite destination dir = %q", plan.To.Dir)
	}
}

func TestDetectPlanSkipsCustomAndPlusPaths(t *testing.T) {
	if _, ok := detectPlan("linux", "/opt/custom/agent", "", ""); ok {
		t.Fatal("custom install dir must not relocate")
	}
	if _, ok := detectPlan("linux", "/opt/lite-plus-agent/Lite-Plus-agent", "", ""); ok {
		t.Fatal("already-plus path must not relocate again")
	}
	if _, ok := detectPlan("windows", `D:\Apps\Lite-Plus-agent.exe`, "", `C:\Program Files`); ok {
		t.Fatal("custom windows dir must not relocate")
	}
}

func TestRewriteLaunchArgsRewritesConfigInOldDir(t *testing.T) {
	got := rewriteLaunchArgs(
		[]string{"/opt/komari/agent", "-e", "example.com", "--config", "/opt/komari/node.json"},
		"/opt/komari",
		"/opt/lite-plus-agent",
		"/opt/lite-plus-agent/Lite-Plus-agent",
		"linux",
	)
	if got[0] != "/opt/lite-plus-agent/Lite-Plus-agent" && filepath.Base(got[0]) != "Lite-Plus-agent" {
		t.Fatalf("argv0 = %q, want new process path", got[0])
	}
	wantConfig := filepath.Join("/opt/lite-plus-agent", "node.json")
	if got[len(got)-1] != wantConfig && filepath.ToSlash(got[len(got)-1]) != "/opt/lite-plus-agent/node.json" {
		t.Fatalf("config path = %q", got[len(got)-1])
	}
}

func TestCopySidecarsAndConfig(t *testing.T) {
	oldDir := t.TempDir()
	newDir := t.TempDir()
	for _, name := range []string{"auto-discovery.json", "net_static.json", "net_static.json.bak"} {
		if err := os.WriteFile(filepath.Join(oldDir, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	config := filepath.Join(oldDir, "node.json")
	if err := os.WriteFile(config, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := copySidecars(oldDir, newDir, runtime.GOOS, []string{config}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"auto-discovery.json", "net_static.json", "net_static.json.bak", "node.json"} {
		if _, err := os.Stat(filepath.Join(newDir, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
}

func TestIsContainerAndCgroup(t *testing.T) {
	if isContainer(func(string) error { return os.ErrNotExist }) {
		t.Fatal("no marker should not look like a container")
	}
	if !isContainer(func(path string) error {
		if path == "/.lite-plus-agent-container" {
			return nil
		}
		return os.ErrNotExist
	}) {
		t.Fatal("plus container marker should skip relocate")
	}
	if !isContainer(func(path string) error {
		if path == "/.lite-agent-container" {
			return nil
		}
		return os.ErrNotExist
	}) {
		t.Fatal("lite container marker should skip relocate")
	}
	if !isContainer(func(path string) error {
		if path == "/.komari-agent-container" {
			return nil
		}
		return os.ErrNotExist
	}) {
		t.Fatal("legacy container marker should skip relocate")
	}

	got := serviceFromCgroup("0::/system.slice/komari-agent.service")
	if got != "komari-agent" {
		t.Fatalf("cgroup service = %q", got)
	}
}

func TestOfficialLaunchdServiceUsesInstallDirectoryNotPlistOrder(t *testing.T) {
	home := "/Users/lite"
	allExist := func(label string) bool {
		return label == "com.komari.komari-agent" || label == "com.lite.lite-agent" || label == "com.liteplus.lite-plus-agent"
	}

	name, ok := officialLaunchdServiceForExecutable("/usr/local/lite-plus-agent/Lite-Plus-agent", home, allExist)
	if !ok || name != plusServiceName {
		t.Fatalf("plus system layout = %q ok=%v, want lite-plus-agent so leftover units can be retired", name, ok)
	}

	name, ok = officialLaunchdServiceForExecutable(filepath.Join(home, ".lite-plus-agent", "Lite-Plus-agent"), home, allExist)
	if !ok || name != plusServiceName {
		t.Fatalf("plus user layout = %q ok=%v, want lite-plus-agent", name, ok)
	}

	name, ok = officialLaunchdServiceForExecutable("/usr/local/lite-agent/Lite-agent", home, allExist)
	if !ok || name != liteServiceName {
		t.Fatalf("lite system layout = %q ok=%v, want lite-agent so directory relocate still runs", name, ok)
	}

	name, ok = officialLaunchdServiceForExecutable("/usr/local/komari/agent", home, allExist)
	if !ok || name != komariServiceName {
		t.Fatalf("legacy system layout = %q ok=%v, want komari-agent so directory relocate still runs", name, ok)
	}

	name, ok = officialLaunchdServiceForExecutable("/opt/custom/Lite-Plus-agent", home, allExist)
	if ok {
		t.Fatalf("custom path must not match just because official plists exist, got %q", name)
	}
}

func TestRetireLeftoverLegacyOnPlusMacLayoutWhenNewPlistNotDetected(t *testing.T) {
	t.Cleanup(restoreRelocateHooks)
	lookupExecutable = func() (string, error) { return "/usr/local/lite-plus-agent/Lite-Plus-agent", nil }
	lookupStat = func(string) error { return os.ErrNotExist }
	ctrl := &fakeController{legacyNames: []string{"komari-agent", "lite-agent"}}
	if err := retireLeftoverLegacy("darwin", ctrl); err != nil {
		t.Fatal(err)
	}
	if len(ctrl.removed) != 2 {
		t.Fatalf("plus agent must retire leftover komari-agent and lite-agent: %v", ctrl.removed)
	}
}

func TestSystemdUnitStartsPlusAgentBinary(t *testing.T) {
	unit := systemdUnit(spec{
		Name:    "lite-plus-agent",
		Binary:  "/opt/lite-plus-agent/Lite-Plus-agent",
		Args:    []string{"-e", "example.com"},
		WorkDir: "/opt/lite-plus-agent",
	})
	if !strings.Contains(unit, "ExecStart=/opt/lite-plus-agent/Lite-Plus-agent") {
		t.Fatalf("unit missing Lite-Plus-agent process path:\n%s", unit)
	}
	if strings.Contains(unit, "/opt/komari/agent") || strings.Contains(unit, "/opt/lite-agent/Lite-agent") {
		t.Fatal("unit still points at an older agent process name")
	}
	if !strings.Contains(unit, "Environment=GODEBUG=disablethp=1") {
		t.Fatalf("unit missing disablethp:\n%s", unit)
	}
}

func TestWithDisableTHPMergesExistingGODEBUG(t *testing.T) {
	got := withDisableTHP(nil)
	if len(got) != 1 || got[0] != "GODEBUG=disablethp=1" {
		t.Fatalf("empty %v", got)
	}
	got = withDisableTHP([]string{"GODEBUG=gctrace=1", "FOO=bar"})
	if got[0] != "GODEBUG=gctrace=1,disablethp=1" || got[1] != "FOO=bar" {
		t.Fatalf("merge %v", got)
	}
	got = withDisableTHP([]string{"GODEBUG=disablethp=1"})
	if len(got) != 1 || got[0] != "GODEBUG=disablethp=1" {
		t.Fatalf("already %v", got)
	}
}
