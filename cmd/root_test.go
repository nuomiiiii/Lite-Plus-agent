package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	pkg_flags "github.com/nuomiiiii/lite-agent/cmd/flags"
	"github.com/nuomiiiii/lite-agent/remotecontrol"
	"github.com/spf13/cobra"
)

func validRuntimeConfig() *pkg_flags.Config {
	return &pkg_flags.Config{
		Interval:           3,
		ReconnectInterval:  5,
		InfoReportInterval: 5,
		MaxRetries:         3,
		ProtocolVersion:    2,
	}
}

func TestValidateRuntimeConfig(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*pkg_flags.Config)
		valid  bool
	}{
		{name: "defaults", valid: true},
		{name: "zero interval", mutate: func(c *pkg_flags.Config) { c.Interval = 0 }},
		{name: "zero reconnect interval", mutate: func(c *pkg_flags.Config) { c.ReconnectInterval = 0 }},
		{name: "zero info interval", mutate: func(c *pkg_flags.Config) { c.InfoReportInterval = 0 }},
		{name: "negative retries", mutate: func(c *pkg_flags.Config) { c.MaxRetries = -1 }},
		{name: "invalid month day", mutate: func(c *pkg_flags.Config) { c.MonthRotate = 32 }},
		{name: "invalid month time", mutate: func(c *pkg_flags.Config) { c.MonthRotateTime = "25:00:00" }},
		{name: "month time ok", mutate: func(c *pkg_flags.Config) { c.MonthRotateTime = "00:00:00" }, valid: true},
		{name: "invalid timezone", mutate: func(c *pkg_flags.Config) { c.MonthRotateTimezone = "Not/AZone" }},
		{name: "shanghai timezone", mutate: func(c *pkg_flags.Config) { c.MonthRotateTimezone = "Asia/Shanghai" }, valid: true},
		{name: "invalid protocol", mutate: func(c *pkg_flags.Config) { c.ProtocolVersion = 3 }},
		{name: "protocol v1 removed", mutate: func(c *pkg_flags.Config) { c.ProtocolVersion = 1 }},
		{name: "protocol 0 means 2", mutate: func(c *pkg_flags.Config) { c.ProtocolVersion = 0 }, valid: true},
		{name: "protocol 2 ok", mutate: func(c *pkg_flags.Config) { c.ProtocolVersion = 2 }, valid: true},
		{name: "ipv4 preferred", mutate: func(c *pkg_flags.Config) { c.PreferIPVersion = "4" }, valid: true},
		{name: "invalid preferred IP", mutate: func(c *pkg_flags.Config) { c.PreferIPVersion = "auto" }},
		{name: "Cloudflare Access credentials", mutate: func(c *pkg_flags.Config) {
			c.CFAccessClientID = "access-id"
			c.CFAccessClientSecret = "access-secret"
		}, valid: true},
		{name: "Cloudflare Access client ID only", mutate: func(c *pkg_flags.Config) { c.CFAccessClientID = "access-id" }},
		{name: "Cloudflare Access client secret only", mutate: func(c *pkg_flags.Config) { c.CFAccessClientSecret = "access-secret" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := validRuntimeConfig()
			if tt.mutate != nil {
				tt.mutate(config)
			}
			err := validateRuntimeConfig(config)
			if tt.valid && err != nil {
				t.Fatalf("validateRuntimeConfig() error = %v", err)
			}
			if !tt.valid && err == nil {
				t.Fatal("validateRuntimeConfig() expected an error")
			}
		})
	}
}

func TestRootCmdEnablesAutoUpdateByDefault(t *testing.T) {
	flag := RootCmd.PersistentFlags().Lookup("disable-auto-update")
	if flag == nil {
		t.Fatal("disable-auto-update flag is missing")
	}
	if flag.DefValue != "false" {
		t.Fatalf("disable-auto-update default = %q, want false", flag.DefValue)
	}
}

func TestRootRestoresFirewallBeforeAutoUpdate(t *testing.T) {
	raw, err := os.ReadFile("root.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	restore := strings.Index(text, "server.RestorePersistedFirewall()")
	watch := strings.Index(text, "go server.WatchPersistedFirewall()")
	update := strings.Index(text, "update.CheckAndUpdate()")
	if restore < 0 || watch < 0 || update < 0 {
		t.Fatal("startup must restore firewall and watch owned rules")
	}
	if restore > update || watch > update {
		t.Fatal("firewall must be restored before CheckAndUpdate so reboot is not a wait-then-deny window")
	}
}

func TestLoadEffectiveConfigPrecedence(t *testing.T) {
	tests := []struct {
		name      string
		fileValue bool
		envValue  string
		args      []string
		want      bool
	}{
		{
			name:      "explicit disable flag overrides config file",
			fileValue: false,
			args:      []string{"--disable-auto-update"},
			want:      true,
		},
		{
			name:      "config file keeps automatic updates enabled",
			fileValue: false,
			want:      false,
		},
		{
			name:      "environment enables automatic updates",
			fileValue: true,
			envValue:  "false",
			want:      false,
		},
		{
			name:      "explicit false flag overrides environment and config",
			fileValue: true,
			envValue:  "true",
			args:      []string{"--disable-auto-update=false"},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "agent.json")
			contents := []byte(`{"disable_auto_update":false}`)
			if tt.fileValue {
				contents = []byte(`{"disable_auto_update":true}`)
			}
			if err := os.WriteFile(configPath, contents, 0o600); err != nil {
				t.Fatal(err)
			}

			t.Setenv("AGENT_CONFIG_FILE", "")
			t.Setenv("AGENT_DISABLE_AUTO_UPDATE", tt.envValue)
			config := &pkg_flags.Config{ConfigFile: configPath}
			command := &cobra.Command{Use: "test"}
			command.Flags().BoolVar(&config.DisableAutoUpdate, "disable-auto-update", false, "")
			command.Flags().StringVar(&config.ConfigFile, "config", configPath, "")
			if err := command.ParseFlags(tt.args); err != nil {
				t.Fatal(err)
			}
			if err := loadEffectiveConfig(command, config); err != nil {
				t.Fatal(err)
			}
			if config.DisableAutoUpdate != tt.want {
				t.Fatalf("DisableAutoUpdate = %v, want %v", config.DisableAutoUpdate, tt.want)
			}
		})
	}
}

func remoteControlTestCommand(config *pkg_flags.Config) *cobra.Command {
	command := &cobra.Command{Use: "test"}
	command.Flags().BoolVar(&config.RemoteControlEnabled, "enable-remote-control", false, "")
	command.Flags().BoolVar(&config.DisableWebSsh, "disable-web-ssh", false, "")
	command.Flags().StringVar(&config.ConfigFile, "config", config.ConfigFile, "")
	return command
}

func withIsolatedRemoteControlState(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), remotecontrol.StateFileName)
	previous := remoteControlStatePath
	previousHost := looksLikePriorHostInstall
	remoteControlStatePath = func() string { return path }
	looksLikePriorHostInstall = func() bool { return false }
	t.Cleanup(func() {
		remoteControlStatePath = previous
		looksLikePriorHostInstall = previousHost
	})
}

func TestJSONWithoutRemoteKeyDefaultsOff(t *testing.T) {
	t.Setenv("AGENT_CONFIG_FILE", "")
	t.Setenv("AGENT_REMOTE_CONTROL_ENABLED", "")
	t.Setenv("AGENT_DISABLE_WEB_SSH", "")
	withIsolatedRemoteControlState(t)
	configPath := filepath.Join(t.TempDir(), "agent.json")
	original := []byte(`{"endpoint":"http://example","token":"secret"}`)
	if err := os.WriteFile(configPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	config := &pkg_flags.Config{ConfigFile: configPath}
	command := remoteControlTestCommand(config)
	if err := command.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}
	if err := loadEffectiveConfig(command, config); err != nil {
		t.Fatal(err)
	}
	if config.RemoteControlEnabled {
		t.Fatal("JSON with only endpoint/token must default remote control off")
	}
	persisted, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(persisted), `"remote_control_enabled"`) {
		t.Fatalf("ordinary JSON must not be rewritten as an old install: %s", persisted)
	}
}

func TestNewManualInstallWithoutRemoteFlagsDefaultsOff(t *testing.T) {
	t.Setenv("AGENT_CONFIG_FILE", "")
	t.Setenv("AGENT_REMOTE_CONTROL_ENABLED", "")
	t.Setenv("AGENT_DISABLE_WEB_SSH", "")
	withIsolatedRemoteControlState(t)
	config := &pkg_flags.Config{}
	command := remoteControlTestCommand(config)
	if err := command.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}
	if err := loadEffectiveConfig(command, config); err != nil {
		t.Fatal(err)
	}
	if config.RemoteControlEnabled {
		t.Fatal("new manual installs without remote flags must default remote control off")
	}
}

func TestStandardLayoutWithoutConfigDefaultsOff(t *testing.T) {
	t.Setenv("AGENT_CONFIG_FILE", "")
	t.Setenv("AGENT_REMOTE_CONTROL_ENABLED", "")
	t.Setenv("AGENT_DISABLE_WEB_SSH", "")
	withIsolatedRemoteControlState(t)
	config := &pkg_flags.Config{}
	command := remoteControlTestCommand(config)
	if err := command.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}
	if err := loadEffectiveConfig(command, config); err != nil {
		t.Fatal(err)
	}
	if config.RemoteControlEnabled {
		t.Fatal("dropping the binary into a standard install directory must not enable remote control")
	}
}

func TestPersistedStateEnablesRemoteControl(t *testing.T) {
	t.Setenv("AGENT_CONFIG_FILE", "")
	t.Setenv("AGENT_REMOTE_CONTROL_ENABLED", "")
	t.Setenv("AGENT_DISABLE_WEB_SSH", "")
	path := filepath.Join(t.TempDir(), remotecontrol.StateFileName)
	if err := remotecontrol.WriteAtomic(path, true); err != nil {
		t.Fatal(err)
	}
	previous := remoteControlStatePath
	remoteControlStatePath = func() string { return path }
	t.Cleanup(func() { remoteControlStatePath = previous })
	config := &pkg_flags.Config{}
	command := remoteControlTestCommand(config)
	if err := command.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}
	if err := loadEffectiveConfig(command, config); err != nil {
		t.Fatal(err)
	}
	if !config.RemoteControlEnabled {
		t.Fatal("trusted persisted migration state must enable remote control")
	}
}

func TestPersistedStateDisablesRemoteControl(t *testing.T) {
	t.Setenv("AGENT_CONFIG_FILE", "")
	t.Setenv("AGENT_REMOTE_CONTROL_ENABLED", "")
	t.Setenv("AGENT_DISABLE_WEB_SSH", "")
	path := filepath.Join(t.TempDir(), remotecontrol.StateFileName)
	if err := remotecontrol.WriteAtomic(path, false); err != nil {
		t.Fatal(err)
	}
	previous := remoteControlStatePath
	remoteControlStatePath = func() string { return path }
	t.Cleanup(func() { remoteControlStatePath = previous })
	config := &pkg_flags.Config{}
	command := remoteControlTestCommand(config)
	if err := command.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}
	if err := loadEffectiveConfig(command, config); err != nil {
		t.Fatal(err)
	}
	if config.RemoteControlEnabled {
		t.Fatal("persisted remote-control=false must stay off")
	}
}

func TestExplicitFlagOverridesPersistedState(t *testing.T) {
	t.Setenv("AGENT_CONFIG_FILE", "")
	t.Setenv("AGENT_REMOTE_CONTROL_ENABLED", "")
	t.Setenv("AGENT_DISABLE_WEB_SSH", "")
	path := filepath.Join(t.TempDir(), remotecontrol.StateFileName)
	if err := remotecontrol.WriteAtomic(path, true); err != nil {
		t.Fatal(err)
	}
	previous := remoteControlStatePath
	remoteControlStatePath = func() string { return path }
	t.Cleanup(func() { remoteControlStatePath = previous })
	config := &pkg_flags.Config{}
	command := remoteControlTestCommand(config)
	if err := command.ParseFlags([]string{"--enable-remote-control=false"}); err != nil {
		t.Fatal(err)
	}
	if err := loadEffectiveConfig(command, config); err != nil {
		t.Fatal(err)
	}
	if config.RemoteControlEnabled {
		t.Fatal("explicit --enable-remote-control=false must win over persisted state")
	}
}

func TestNewInstallExplicitlyDisablesRemoteControl(t *testing.T) {
	t.Setenv("AGENT_CONFIG_FILE", "")
	t.Setenv("AGENT_REMOTE_CONTROL_ENABLED", "")
	t.Setenv("AGENT_DISABLE_WEB_SSH", "")
	withIsolatedRemoteControlState(t)
	config := &pkg_flags.Config{}
	command := remoteControlTestCommand(config)
	if err := command.ParseFlags([]string{"--enable-remote-control=false"}); err != nil {
		t.Fatal(err)
	}
	if err := loadEffectiveConfig(command, config); err != nil {
		t.Fatal(err)
	}
	if config.RemoteControlEnabled {
		t.Fatal("new install --enable-remote-control=false must keep remote control off")
	}
}

func TestDisableWebSshTrueMigratesToRemoteControlDisabled(t *testing.T) {
	t.Setenv("AGENT_CONFIG_FILE", "")
	t.Setenv("AGENT_REMOTE_CONTROL_ENABLED", "")
	t.Setenv("AGENT_DISABLE_WEB_SSH", "")
	withIsolatedRemoteControlState(t)
	configPath := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(configPath, []byte(`{"disable_web_ssh":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	config := &pkg_flags.Config{ConfigFile: configPath}
	command := remoteControlTestCommand(config)
	if err := command.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}
	if err := loadEffectiveConfig(command, config); err != nil {
		t.Fatal(err)
	}
	if config.RemoteControlEnabled {
		t.Fatal("disable_web_ssh true must migrate to remote_control_enabled false")
	}
	persisted, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(persisted), `"remote_control_enabled"`) {
		t.Fatalf("migrated config missing remote_control_enabled: %s", persisted)
	}
	if strings.Contains(string(persisted), "disable_web_ssh") {
		t.Fatalf("migrated config still has disable_web_ssh: %s", persisted)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(configPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("migrated config mode = %o, want 0600", info.Mode().Perm())
		}
	}
}

func TestDisableWebSshFalseMigratesToRemoteControlEnabled(t *testing.T) {
	t.Setenv("AGENT_CONFIG_FILE", "")
	t.Setenv("AGENT_REMOTE_CONTROL_ENABLED", "")
	t.Setenv("AGENT_DISABLE_WEB_SSH", "")
	withIsolatedRemoteControlState(t)
	configPath := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(configPath, []byte(`{"disable_web_ssh":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	config := &pkg_flags.Config{ConfigFile: configPath}
	command := remoteControlTestCommand(config)
	if err := command.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}
	if err := loadEffectiveConfig(command, config); err != nil {
		t.Fatal(err)
	}
	if !config.RemoteControlEnabled {
		t.Fatal("old configs with disable_web_ssh false must stay enabled")
	}
	persisted, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(persisted), `"remote_control_enabled": true`) &&
		!strings.Contains(string(persisted), `"remote_control_enabled":true`) {
		t.Fatalf("enabled migration was not persisted: %s", persisted)
	}
	if strings.Contains(string(persisted), "disable_web_ssh") {
		t.Fatalf("migrated config still has disable_web_ssh: %s", persisted)
	}
}

func TestDisableWebSshPersistFailureAborts(t *testing.T) {
	t.Setenv("AGENT_CONFIG_FILE", "")
	t.Setenv("AGENT_REMOTE_CONTROL_ENABLED", "")
	t.Setenv("AGENT_DISABLE_WEB_SSH", "")
	withIsolatedRemoteControlState(t)
	configPath := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(configPath, []byte(`{"disable_web_ssh":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := persistMigratedRemoteControlFn
	persistMigratedRemoteControlFn = func(string, bool) error { return errors.New("persist failed") }
	t.Cleanup(func() { persistMigratedRemoteControlFn = previous })
	config := &pkg_flags.Config{ConfigFile: configPath}
	command := remoteControlTestCommand(config)
	if err := command.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}
	if err := loadEffectiveConfig(command, config); err == nil {
		t.Fatal("migration persist failure must abort startup")
	}
	persisted, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(persisted), "disable_web_ssh") {
		t.Fatalf("failed persist must leave the original config: %s", persisted)
	}
}

func TestEnvRemoteControlEnabled(t *testing.T) {
	t.Setenv("AGENT_CONFIG_FILE", "")
	t.Setenv("AGENT_REMOTE_CONTROL_ENABLED", "true")
	t.Setenv("AGENT_DISABLE_WEB_SSH", "")
	withIsolatedRemoteControlState(t)
	config := &pkg_flags.Config{}
	command := remoteControlTestCommand(config)
	if err := command.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}
	if err := loadEffectiveConfig(command, config); err != nil {
		t.Fatal(err)
	}
	if !config.RemoteControlEnabled {
		t.Fatal("AGENT_REMOTE_CONTROL_ENABLED=true must enable remote control")
	}
}

func TestRemoteControlFlagWinsOverDisableWebSsh(t *testing.T) {
	t.Setenv("AGENT_CONFIG_FILE", "")
	t.Setenv("AGENT_REMOTE_CONTROL_ENABLED", "")
	t.Setenv("AGENT_DISABLE_WEB_SSH", "")
	withIsolatedRemoteControlState(t)
	config := &pkg_flags.Config{}
	command := remoteControlTestCommand(config)
	if err := command.ParseFlags([]string{"--enable-remote-control", "--disable-web-ssh"}); err != nil {
		t.Fatal(err)
	}
	if err := loadEffectiveConfig(command, config); err != nil {
		t.Fatal(err)
	}
	if !config.RemoteControlEnabled {
		t.Fatal("explicit --enable-remote-control must win over --disable-web-ssh")
	}
}

func TestEnableRemoteControlFalseWinsOverLegacyDisableWebSshJSON(t *testing.T) {
	t.Setenv("AGENT_CONFIG_FILE", "")
	t.Setenv("AGENT_REMOTE_CONTROL_ENABLED", "")
	t.Setenv("AGENT_DISABLE_WEB_SSH", "")
	withIsolatedRemoteControlState(t)
	configPath := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(configPath, []byte(`{"disable_web_ssh":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	config := &pkg_flags.Config{ConfigFile: configPath}
	command := remoteControlTestCommand(config)
	if err := command.ParseFlags([]string{"--enable-remote-control=false"}); err != nil {
		t.Fatal(err)
	}
	if err := loadEffectiveConfig(command, config); err != nil {
		t.Fatal(err)
	}
	if config.RemoteControlEnabled {
		t.Fatal("--enable-remote-control=false must win over disable_web_ssh false")
	}
	persisted, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(persisted), "disable_web_ssh") {
		t.Fatalf("migrated config still has disable_web_ssh: %s", persisted)
	}
	if !strings.Contains(string(persisted), `"remote_control_enabled": false`) &&
		!strings.Contains(string(persisted), `"remote_control_enabled":false`) {
		t.Fatalf("migrated config missing remote_control_enabled false: %s", persisted)
	}
}

func TestEnableRemoteControlFlagMigratesDisableWebSshFile(t *testing.T) {
	t.Setenv("AGENT_CONFIG_FILE", "")
	t.Setenv("AGENT_REMOTE_CONTROL_ENABLED", "")
	t.Setenv("AGENT_DISABLE_WEB_SSH", "")
	withIsolatedRemoteControlState(t)
	configPath := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(configPath, []byte(`{"disable_web_ssh":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	config := &pkg_flags.Config{ConfigFile: configPath}
	command := remoteControlTestCommand(config)
	if err := command.ParseFlags([]string{"--enable-remote-control"}); err != nil {
		t.Fatal(err)
	}
	if err := loadEffectiveConfig(command, config); err != nil {
		t.Fatal(err)
	}
	if !config.RemoteControlEnabled {
		t.Fatal("installer --enable-remote-control must start even when JSON still has disable_web_ssh")
	}
	persisted, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(persisted), "disable_web_ssh") {
		t.Fatalf("migrated config still has disable_web_ssh: %s", persisted)
	}
	if !strings.Contains(string(persisted), `"remote_control_enabled"`) {
		t.Fatalf("migrated config missing remote_control_enabled: %s", persisted)
	}
}

func TestRemoteControlFileKeyMigratesDisableWebSsh(t *testing.T) {
	t.Setenv("AGENT_CONFIG_FILE", "")
	t.Setenv("AGENT_REMOTE_CONTROL_ENABLED", "")
	t.Setenv("AGENT_DISABLE_WEB_SSH", "")
	withIsolatedRemoteControlState(t)
	configPath := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(configPath, []byte(`{"remote_control_enabled":false,"disable_web_ssh":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	config := &pkg_flags.Config{ConfigFile: configPath}
	command := remoteControlTestCommand(config)
	if err := command.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}
	if err := loadEffectiveConfig(command, config); err != nil {
		t.Fatal(err)
	}
	if config.RemoteControlEnabled {
		t.Fatal("remote_control_enabled false must win over leftover disable_web_ssh")
	}
	persisted, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(persisted), "disable_web_ssh") {
		t.Fatalf("migrated config still has disable_web_ssh: %s", persisted)
	}
}

func TestPriorHostInstallKeepsRemoteControlOn(t *testing.T) {
	t.Setenv("AGENT_CONFIG_FILE", "")
	t.Setenv("AGENT_REMOTE_CONTROL_ENABLED", "")
	t.Setenv("AGENT_DISABLE_WEB_SSH", "")
	path := filepath.Join(t.TempDir(), remotecontrol.StateFileName)
	previous := remoteControlStatePath
	previousHost := looksLikePriorHostInstall
	remoteControlStatePath = func() string { return path }
	looksLikePriorHostInstall = func() bool { return true }
	t.Cleanup(func() {
		remoteControlStatePath = previous
		looksLikePriorHostInstall = previousHost
	})
	config := &pkg_flags.Config{}
	command := remoteControlTestCommand(config)
	if err := command.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}
	if err := loadEffectiveConfig(command, config); err != nil {
		t.Fatal(err)
	}
	if !config.RemoteControlEnabled {
		t.Fatal("komari-agent and Lite-agent 2.3.0.2 host upgrades must keep remote control on")
	}
	enabled, ok, err := remotecontrol.Read(path)
	if err != nil || !ok || !enabled {
		t.Fatalf("prior host install must persist remote-control.state enabled=%t ok=%t err=%v", enabled, ok, err)
	}
}

func TestLoadEffectiveConfigReadsLegacyAutoDiscoveryMarker(t *testing.T) {
	t.Setenv("AGENT_CONFIG_FILE", "")
	t.Setenv("AGENT_AUTO_DISCOVERY_KEY", "")
	t.Setenv("AGENT_TOKEN", "")
	withIsolatedRemoteControlState(t)

	configPath := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(configPath, []byte(`{"endpoint":"http://example","auto_discovery_key":"legacy-key"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	config := &pkg_flags.Config{ConfigFile: configPath}
	command := &cobra.Command{Use: "test"}
	command.Flags().StringVar(&config.Token, "token", "", "")
	command.Flags().StringVar(&config.AutoDiscoveryKey, "auto-discovery", "", "")
	command.Flags().StringVar(&config.ConfigFile, "config", configPath, "")
	if err := command.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}
	if err := loadEffectiveConfig(command, config); err != nil {
		t.Fatal(err)
	}
	if config.Token != "" {
		t.Fatalf("JSON without token must leave Token empty, got %q", config.Token)
	}
	if config.AutoDiscoveryKey != "legacy-key" {
		t.Fatalf("JSON auto_discovery_key = %q", config.AutoDiscoveryKey)
	}

	t.Setenv("AGENT_AUTO_DISCOVERY_KEY", "env-key")
	config = &pkg_flags.Config{}
	command = &cobra.Command{Use: "test"}
	command.Flags().StringVar(&config.Token, "token", "", "")
	command.Flags().StringVar(&config.AutoDiscoveryKey, "auto-discovery", "", "")
	command.Flags().StringVar(&config.ConfigFile, "config", "", "")
	if err := command.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}
	if err := loadEffectiveConfig(command, config); err != nil {
		t.Fatal(err)
	}
	if config.AutoDiscoveryKey != "env-key" {
		t.Fatalf("AGENT_AUTO_DISCOVERY_KEY = %q", config.AutoDiscoveryKey)
	}
}
