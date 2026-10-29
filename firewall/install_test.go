package firewall

import (
	"os"
	"strings"
	"testing"
)

func TestNftablesInstallDoesNotEnableDistroService(t *testing.T) {
	src, err := os.ReadFile("install_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	if !strings.Contains(text, `"systemctl", "disable", "--now", "nftables"`) {
		t.Fatal("installing nftables must disable distro nftables.service so its policy drop cannot shadow Plus allows")
	}
	if strings.Contains(text, `"enable"`) {
		t.Fatal("installing nftables must not enable nftables.service")
	}
}

func TestNftablesInstallPlanPicksPackageManager(t *testing.T) {
	got := nftablesInstallPlan(func(name string) bool { return name == "apt-get" })
	if len(got) != 2 || got[1].Name != "apt-get" || got[1].Args[len(got[1].Args)-1] != "nftables" {
		t.Fatalf("apt plan: %+v", got)
	}
	got = nftablesInstallPlan(func(name string) bool { return name == "dnf" })
	if len(got) != 1 || got[0].Name != "dnf" {
		t.Fatalf("dnf plan: %+v", got)
	}
	if plan := nftablesInstallPlan(func(string) bool { return false }); plan != nil {
		t.Fatalf("empty plan: %+v", plan)
	}
}
