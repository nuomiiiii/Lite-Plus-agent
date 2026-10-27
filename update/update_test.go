package update

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nuomiiiii/lite-agent/cmd/flags"
	"github.com/nuomiiiii/lite-agent/remotecontrol"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
)

func TestDefaultUpdateRepo(t *testing.T) {
	if CurrentVersion != "0.0.1.9" {
		t.Fatalf("CurrentVersion = %q, want 0.0.1.9", CurrentVersion)
	}
	if Repo != "nuomiiiii/Lite-Plus-agent" {
		t.Fatalf("Repo = %q, want nuomiiiii/Lite-Plus-agent", Repo)
	}
}

func TestUpdateChannelRejectsLiteRepos(t *testing.T) {
	previous := Repo
	t.Cleanup(func() { Repo = previous })
	Repo = ""
	if updateChannelConfigured() {
		t.Fatal("empty Repo must not count as a Plus channel")
	}
	Repo = "nuomiiiii/Lite-agent"
	if updateChannelConfigured() {
		t.Fatal("Lite-agent must not count as a Plus channel")
	}
	Repo = "acme/lite-plus-agent"
	if !updateChannelConfigured() {
		t.Fatal("an independent Plus repo should be accepted")
	}
}

func TestCheckAndUpdateSkipsUnconfiguredChannel(t *testing.T) {
	previous := Repo
	t.Cleanup(func() { Repo = previous })
	Repo = ""
	if err := CheckAndUpdate(); err != nil {
		t.Fatalf("CheckAndUpdate() error = %v", err)
	}
}

// TestParseVersion 验证 parseVersion 能够解析各种版本号格式，包括带 v/V 前缀、预发布和构建元数据
func TestParseVersion(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"v1.2.3", "1.2.3"},
		{"V1.2.3", "1.2.3"},
		{"1.2.3-beta.1", "1.2.3-beta.1"},
		{"v1.2.3+meta", "1.2.3+meta"},
		{"1.2.3-pre.1+build.123", "1.2.3-pre.1+build.123"},
		{"2.1.11.0", "2.1.11.0"},
		{"v2.1.11.1+meta", "2.1.11.1+meta"},
		{"  v2.0.0  ", "2.0.0"},
		{"invalid", ""},
	}

	for _, tt := range tests {
		got, err := parseVersion(strings.TrimSpace(tt.input))
		if tt.want == "" {
			if err == nil {
				t.Errorf("parseVersion(%q) expected error, got %v", tt.input, got)
			}
		} else {
			if err != nil {
				t.Errorf("parseVersion(%q) unexpected error: %v", tt.input, err)
				continue
			}
			if got.String() != tt.want {
				t.Errorf("parseVersion(%q) = %q, want %q", tt.input, got.String(), tt.want)
			}
		}
	}
}

func TestBumpPatch(t *testing.T) {
	got, err := BumpPatch("0.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if got != "0.0.0.2" {
		t.Fatalf("BumpPatch(0.0.0.1) = %q, want 0.0.0.2", got)
	}
	got, err = BumpPatch("0.0.0.1+abc1234")
	if err != nil {
		t.Fatal(err)
	}
	if got != "0.0.0.2" {
		t.Fatalf("BumpPatch(0.0.0.1+abc1234) = %q, want 0.0.0.2", got)
	}
	if _, err := BumpPatch("1.2.3"); err == nil {
		t.Fatal("BumpPatch(1.2.3) expected error for three-part version")
	}
}

// TestNeedUpdate 验证 needUpdate 在不同版本组合下的判断
func TestNeedUpdate(t *testing.T) {
	tests := []struct {
		current string
		latest  string
		want    bool
	}{
		{"1.0.0", "1.0.1", true},
		{"v1.0.0", "1.1.0", true},
		{"1.2.3", "1.2.3", false},
		{"1.2.4", "1.2.3", false},
		{"1.2.3-beta", "1.2.3", true},
		{"1.2.3", "1.2.3-beta", false},
		{"0.0.5", "0.0.6+build.1", true},
		{"0.0.6", "v0.0.6+build.1", false},
		{"2.1.6+65a346e", "2.1.61", true},
		{"2.1.61+be3daa4", "2.1.61", false},
		{"2.1.61", "2.1.62", true},
		{"2.1.62", "2.1.7", true},
		{"2.1.7", "2.1.62", false},
		{"2.1.79", "2.1.8", true},
		{"2.1.8", "2.1.79", false},
		{"2.1.99", "2.1.10", true},
		{"2.1.62", "2.1.11", true},
		{"2.1.10", "2.1.11", true},
		{"2.1.11", "2.1.11.0", false},
		{"2.1.11.0", "2.1.11", false},
		{"2.1.11", "2.1.11.1", true},
		{"2.1.11.1", "2.1.11.2", true},
		{"2.1.11.2", "2.1.11.1", false},
		{"2.1.11.99", "2.1.12.0", true},
		{"2.2.0.1", "2.2.0.2", true},
		{"2.2.0.1+b14011e", "2.2.0.2", true},
		{"2.2.0.2+deadbee", "2.2.0.2", false},
		{"2.2.0.2", "2.2.0.1", false},
		{"2.2.0.2", "2.3.0.0", true},
		{"2.3.0.0+abc1234", "2.3.0.0", false},
		{"2.3.0.0", "2.3.0.1", true},
		{"2.3.0.1+abc1234", "2.3.0.1", false},
		{"2.3.0.1", "2.3.0.2", true},
		{"2.3.0.2+abc1234", "2.3.0.2", false},
		{"2.3.0.2", "2.3.1.0", true},
		{"2.3.1.0+abc1234", "2.3.1.0", false},
		{"2.3.1.0", "2.3.1.1", true},
		{"2.3.1.1+abc1234", "2.3.1.1", false},
		{"2.3.1.1", "2.3.3.0", true},
		{"2.3.3.0+abc1234", "2.3.3.0", false},
		{"2.3.3.0", "2.3.3.1", true},
		{"2.3.3.1+abc1234", "2.3.3.1", false},
		{"2.3.3.1", "2.3.3.2", true},
		{"2.3.3.2+abc1234", "2.3.3.2", false},
		{"2.3.3.2", "2.3.3.3", true},
		{"2.3.3.3+abc1234", "2.3.3.3", false},
		{"2.3.3.3", "2.3.3.4", true},
		{"2.3.3.4+abc1234", "2.3.3.4", false},
		{"2.3.3.4", "2.3.3.5", true},
		{"2.3.3.5+abc1234", "2.3.3.5", false},
		{"2.3.3.5", "2.3.3.6", true},
		{"2.3.3.6+abc1234", "2.3.3.6", false},
		{"2.3.3.6", "2.3.3.7", true},
		{"2.3.3.7+abc1234", "2.3.3.7", false},
		{"2.3.3.7", "2.3.6.0", true},
		{"2.3.6.0+abc1234", "2.3.6.0", false},
		{"2.3.6.0", "2.3.6.1", true},
		{"2.3.6.1+abc1234", "2.3.6.1", false},
		{"2.3.6.1", "2.3.6.2", true},
		{"2.3.6.2+abc1234", "2.3.6.2", false},
		{"2.3.6.2", "2.3.6.3", true},
		{"2.3.6.3+abc1234", "2.3.6.3", false},
		{"2.3.6.3", "2.3.6.4", true},
		{"2.3.6.4+abc1234", "2.3.6.4", false},
		{"2.3.6.4", "2.3.10.0", true},
		{"2.3.10.0+abc1234", "2.3.10.0", false},
		{"0.0.0.1", "0.0.0.2", true},
		{"0.0.0.1+abc1234", "0.0.0.2", true},
		{"0.0.0.1+abc1234", "0.0.0.1", false},
		{"0.0.0.2", "0.0.0.3", true},
		{"0.0.0.2+abc1234", "0.0.0.3", true},
		{"0.0.0.2+abc1234", "0.0.0.2", false},
		{"0.0.0.3", "0.0.0.4", true},
		{"0.0.0.3+abc1234", "0.0.0.4", true},
		{"0.0.0.3+abc1234", "0.0.0.3", false},
		{"0.0.0.4", "0.0.0.5", true},
		{"0.0.0.4+abc1234", "0.0.0.5", true},
		{"0.0.0.4+abc1234", "0.0.0.4", false},
		{"0.0.0.5", "0.0.0.6", true},
		{"0.0.0.5+abc1234", "0.0.0.6", true},
		{"0.0.0.5+abc1234", "0.0.0.5", false},
		{"0.0.0.6+abc1234", "0.0.0.6", false},
		{"2.3.10.0", "2.3.10.1", true},
		{"2.3.10.1+abc1234", "2.3.10.1", false},
		{"0.0.0.6", "0.0.0.7", true},
		{"0.0.0.6+abc1234", "0.0.0.7", true},
		{"0.0.0.7+abc1234", "0.0.0.7", false},
		{"0.0.0.7", "0.0.0.8", true},
		{"0.0.0.7+abc1234", "0.0.0.8", true},
		{"0.0.0.8+abc1234", "0.0.0.8", false},
		{"0.0.0.8", "0.0.0.9", true},
		{"0.0.0.8+abc1234", "0.0.0.9", true},
		{"0.0.0.9+abc1234", "0.0.0.9", false},
		{"0.0.0.9", "0.0.1.0", true},
		{"0.0.0.9+abc1234", "0.0.1.0", true},
		{"0.0.1.0+abc1234", "0.0.1.0", false},
		{"0.0.1.0", "0.0.1.1", true},
		{"0.0.1.0+abc1234", "0.0.1.1", true},
		{"0.0.1.1+abc1234", "0.0.1.1", false},
		{"0.0.1.1", "0.0.1.2", true},
		{"0.0.1.1+abc1234", "0.0.1.2", true},
		{"0.0.1.2+abc1234", "0.0.1.2", false},
		{"0.0.1.2", "0.0.1.3", true},
		{"0.0.1.2+abc1234", "0.0.1.3", true},
		{"0.0.1.3+abc1234", "0.0.1.3", false},
		{"0.0.1.3", "0.0.1.4", true},
		{"0.0.1.3+abc1234", "0.0.1.4", true},
		{"0.0.1.4+abc1234", "0.0.1.4", false},
		{"0.0.1.4", "0.0.1.5", true},
		{"0.0.1.4+abc1234", "0.0.1.5", true},
		{"0.0.1.5+abc1234", "0.0.1.5", false},
		{"0.0.1.5", "0.0.1.6", true},
		{"0.0.1.5+abc1234", "0.0.1.6", true},
		{"0.0.1.6+abc1234", "0.0.1.6", false},
		{"0.0.1.6", "0.0.1.7", true},
		{"0.0.1.6+abc1234", "0.0.1.7", true},
		{"0.0.1.7+abc1234", "0.0.1.7", false},
		{"0.0.1.7", "0.0.1.8", true},
		{"0.0.1.7+abc1234", "0.0.1.8", true},
		{"0.0.1.8+abc1234", "0.0.1.8", false},
		{"0.0.1.8", "0.0.1.9", true},
		{"0.0.1.8+abc1234", "0.0.1.9", true},
		{"0.0.1.9+abc1234", "0.0.1.9", false},
	}

	for _, tt := range tests {
		cur, err := parseVersion(strings.TrimSpace(tt.current))
		if err != nil {
			t.Fatalf("parseVersion(%q) error: %v", tt.current, err)
		}
		lat, err := parseVersion(strings.TrimSpace(tt.latest))
		if err != nil {
			t.Fatalf("parseVersion(%q) error: %v", tt.latest, err)
		}
		got := needUpdate(cur, lat)
		if got != tt.want {
			t.Errorf("needUpdate(%q, %q) = %v, want %v", tt.current, tt.latest, got, tt.want)
		}
	}
}

func TestDetectBuildTrack(t *testing.T) {
	tests := []struct {
		version string
		want    buildTrack
	}{
		{"v1.2.3", stableTrack},
		{"1.2.3", stableTrack},
		{"Snapshot-2607061200", snapshotTrack},
		{"Snapshot-2.1.11-2607282100", snapshotTrack},
		{"invalid", stableTrack},
	}

	for _, tt := range tests {
		got := detectBuildTrack(tt.version)
		if got != tt.want {
			t.Errorf("detectBuildTrack(%q) = %v, want %v", tt.version, got, tt.want)
		}
	}

	if _, err := parseVersion("invalid"); err == nil {
		t.Errorf("invalid non-snapshot version should still fail semver parsing")
	}
}

func TestExpectedAssetName(t *testing.T) {
	tests := []struct {
		goos   string
		goarch string
		want   string
	}{
		{"linux", "amd64", "Lite-Plus-agent-linux-amd64"},
		{"darwin", "arm64", "Lite-Plus-agent-darwin-arm64"},
		{"windows", "amd64", "Lite-Plus-agent-windows-amd64.exe"},
	}

	for _, tt := range tests {
		got := expectedAssetName(tt.goos, tt.goarch)
		if got != tt.want {
			t.Errorf("expectedAssetName(%q, %q) = %q, want %q", tt.goos, tt.goarch, got, tt.want)
		}
	}
}

func TestFindReleaseAssetUsesLiteAgentName(t *testing.T) {
	release := testRelease("2.3.0.0", false, false, time.Now(), "Lite-Plus-agent-linux-amd64")
	asset, ok := findReleaseAsset(release, expectedAssetNames("linux", "amd64")...)
	if !ok {
		t.Fatal("findReleaseAsset() found no candidate")
	}
	if asset.Name != "Lite-Plus-agent-linux-amd64" {
		t.Fatalf("findReleaseAsset() = %q, want Lite-Plus-agent-linux-amd64", asset.Name)
	}
}

func TestFindReleaseAssetIgnoresKomariAgentName(t *testing.T) {
	release := testRelease("2.3.0.0", false, false, time.Now(), "komari-agent-linux-amd64")
	if _, ok := findReleaseAsset(release, expectedAssetNames("linux", "amd64")...); ok {
		t.Fatal("findReleaseAsset() should not accept komari-agent assets")
	}
}

func TestSelectLatestSnapshotRelease(t *testing.T) {
	assetName := "Lite-Plus-agent-linux-amd64"
	base := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)

	releases := []githubRelease{
		testRelease("v9.9.9", false, false, base.Add(5*time.Hour), assetName),
		testRelease("Snapshot-2607061400", true, true, base.Add(4*time.Hour), assetName),
		testRelease("beta-2607061500", true, false, base.Add(6*time.Hour), assetName),
		testRelease("Snapshot-2607061600", true, false, base.Add(7*time.Hour), "Lite-Plus-agent-linux-arm64"),
		testRelease("Snapshot-2607061200", true, false, base, assetName),
		testRelease("Snapshot-2607061300", true, false, base.Add(time.Hour), assetName),
	}

	got, ok := selectLatestSnapshotRelease(releases, assetName)
	if !ok {
		t.Fatalf("selectLatestSnapshotRelease() found no candidate")
	}
	if got.TagName != "Snapshot-2607061300" {
		t.Errorf("selectLatestSnapshotRelease() tag = %q, want %q", got.TagName, "Snapshot-2607061300")
	}
	if got.Asset.Name != assetName {
		t.Errorf("selectLatestSnapshotRelease() asset = %q, want %q", got.Asset.Name, assetName)
	}
}

func TestSelectLatestSnapshotReleaseTieBreaksByTag(t *testing.T) {
	assetName := "Lite-Plus-agent-linux-amd64"
	publishedAt := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)

	releases := []githubRelease{
		testRelease("Snapshot-2607061200", true, false, publishedAt, assetName),
		testRelease("Snapshot-2607061201", true, false, publishedAt, assetName),
	}

	got, ok := selectLatestSnapshotRelease(releases, assetName)
	if !ok {
		t.Fatalf("selectLatestSnapshotRelease() found no candidate")
	}
	if got.TagName != "Snapshot-2607061201" {
		t.Errorf("selectLatestSnapshotRelease() tag = %q, want %q", got.TagName, "Snapshot-2607061201")
	}
}

func TestSelectLatestSnapshotReleaseNoMatch(t *testing.T) {
	releases := []githubRelease{
		testRelease("v1.2.3", false, false, time.Now(), "Lite-Plus-agent-linux-amd64"),
		testRelease("Snapshot-2607061200", true, true, time.Now(), "Lite-Plus-agent-linux-amd64"),
		testRelease("Snapshot-2607061300", true, false, time.Now(), "Lite-Plus-agent-linux-arm64"),
	}

	if got, ok := selectLatestSnapshotRelease(releases, "Lite-Plus-agent-linux-amd64"); ok {
		t.Fatalf("selectLatestSnapshotRelease() = %+v, want no candidate", got)
	}
}

func TestSelectLatestStableRelease(t *testing.T) {
	assetName := "Lite-Plus-agent-linux-amd64"
	base := time.Date(2026, 7, 24, 0, 0, 0, 0, time.UTC)
	releases := []githubRelease{
		testRelease("2.1.6", false, false, base, assetName),
		testRelease("Snapshot-2607240100", true, false, base.Add(time.Hour), assetName),
		testRelease("2.1.61", false, false, base.Add(2*time.Hour), assetName),
		testRelease("2.2.0", false, true, base.Add(3*time.Hour), assetName),
		testRelease("not-semver", false, false, base.Add(4*time.Hour), assetName),
	}

	got, ok := selectLatestStableRelease(releases, assetName)
	if !ok {
		t.Fatal("selectLatestStableRelease() found no candidate")
	}
	if got.TagName != "2.1.61" {
		t.Errorf("selectLatestStableRelease() tag = %q, want %q", got.TagName, "2.1.61")
	}
	if !got.HasAsset || got.Asset.Name != assetName {
		t.Errorf("selectLatestStableRelease() asset = %+v, want %q", got.Asset, assetName)
	}
}

func TestSelectLatestStableReleaseWaitsForNewestAsset(t *testing.T) {
	assetName := "Lite-Plus-agent-linux-amd64"
	base := time.Date(2026, 7, 24, 0, 0, 0, 0, time.UTC)
	releases := []githubRelease{
		testRelease("2.1.6", false, false, base, assetName),
		testRelease("2.1.61", false, false, base.Add(time.Hour), "Lite-Plus-agent-linux-arm64"),
	}

	got, ok := selectLatestStableRelease(releases, assetName)
	if !ok {
		t.Fatal("selectLatestStableRelease() found no candidate")
	}
	if got.TagName != "2.1.61" || got.HasAsset {
		t.Errorf("selectLatestStableRelease() = %+v, want newest release without a ready amd64 asset", got)
	}
}

func TestSelectLatestStableReleaseUsesRevisionOrder(t *testing.T) {
	assetName := "Lite-Plus-agent-linux-amd64"
	base := time.Date(2026, 7, 27, 0, 0, 0, 0, time.UTC)
	releases := []githubRelease{
		testRelease("2.1.62", false, false, base.Add(3*time.Hour), assetName),
		testRelease("2.1.7", false, false, base.Add(2*time.Hour), assetName),
		testRelease("2.1.79", false, false, base.Add(time.Hour), assetName),
		testRelease("2.1.8", false, false, base, assetName),
	}

	got, ok := selectLatestStableRelease(releases, assetName)
	if !ok {
		t.Fatal("selectLatestStableRelease() found no candidate")
	}
	if got.TagName != "2.1.8" {
		t.Errorf("selectLatestStableRelease() tag = %q, want %q", got.TagName, "2.1.8")
	}
}

func TestSelectLatestStableReleaseSupportsFourPartVersions(t *testing.T) {
	assetName := "Lite-Plus-agent-linux-amd64"
	base := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	releases := []githubRelease{
		testRelease("2.1.11", false, false, base.Add(4*time.Hour), assetName),
		testRelease("2.1.11.2", false, false, base.Add(2*time.Hour), assetName),
		testRelease("2.1.11.1", false, false, base.Add(3*time.Hour), assetName),
		testRelease("2.1.12.0", false, false, base, assetName),
	}

	got, ok := selectLatestStableRelease(releases, assetName)
	if !ok {
		t.Fatal("selectLatestStableRelease() found no candidate")
	}
	if got.TagName != "2.1.12.0" || got.Version.String() != "2.1.12.0" {
		t.Errorf("selectLatestStableRelease() = %+v, want 2.1.12.0", got)
	}
}

func TestStableAgentUpdatesFrom2111To2200(t *testing.T) {
	current, err := parseVersion("2.1.11.1+current")
	if err != nil {
		t.Fatalf("parse current version: %v", err)
	}
	latest, err := parseVersion("2.2.0.0")
	if err != nil {
		t.Fatalf("parse latest version: %v", err)
	}
	if !needUpdate(current, latest) {
		t.Fatal("2.1.11.1 should update to 2.2.0.0")
	}
}

func TestNextCheckDelay(t *testing.T) {
	if got := nextCheckDelay(false); got != 6*time.Hour {
		t.Errorf("nextCheckDelay(false) = %s, want 6h", got)
	}
	if got := nextCheckDelay(true); got != 15*time.Minute {
		t.Errorf("nextCheckDelay(true) = %s, want 15m", got)
	}
}

func TestSnapshotNeedsUpdate(t *testing.T) {
	latest := snapshotReleaseCandidate{TagName: "Snapshot-2607061200"}

	if snapshotNeedsUpdate("Snapshot-2607061200", latest) {
		t.Errorf("snapshotNeedsUpdate() should be false for the current snapshot tag")
	}
	if !snapshotNeedsUpdate("Snapshot-2607061100", latest) {
		t.Errorf("snapshotNeedsUpdate() should be true for an older snapshot tag")
	}
}

func testRelease(tag string, prerelease, draft bool, publishedAt time.Time, assetNames ...string) githubRelease {
	assets := make([]githubReleaseAsset, 0, len(assetNames))
	for i, name := range assetNames {
		assets = append(assets, githubReleaseAsset{
			ID:                 int64(i + 1),
			Name:               name,
			Size:               1024,
			BrowserDownloadURL: "https://example.com/" + name,
		})
	}

	return githubRelease{
		TagName:     tag,
		Name:        tag,
		Body:        tag,
		Draft:       draft,
		Prerelease:  prerelease,
		HTMLURL:     "https://example.com/" + tag,
		PublishedAt: publishedAt,
		Assets:      assets,
	}
}

func TestReplaceAgentBinaryPersistsRemoteControlBeforeUpdate(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "Lite-Plus-agent")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	previousPersist := persistRemoteControlState
	previousUpdate := updateBinaryTo
	previousEnabled := flags_pkg.GlobalConfig.RemoteControlEnabled
	t.Cleanup(func() {
		persistRemoteControlState = previousPersist
		updateBinaryTo = previousUpdate
		flags_pkg.GlobalConfig.RemoteControlEnabled = previousEnabled
	})
	flags_pkg.GlobalConfig.RemoteControlEnabled = true
	updated := false
	persistRemoteControlState = persistRemoteControlBeforeReplace
	updateBinaryTo = func(*selfupdate.Updater, *selfupdate.Release, string) error {
		enabled, ok, err := remotecontrol.Read(remotecontrol.PathForExecutable(exe))
		if err != nil || !ok || !enabled {
			t.Errorf("state before replace enabled=%t ok=%t err=%v", enabled, ok, err)
		}
		updated = true
		return nil
	}
	if err := replaceAgentBinary(nil, &selfupdate.Release{}, exe); err != nil {
		t.Fatal(err)
	}
	if !updated {
		t.Fatal("binary replace was skipped")
	}
}

func TestReplaceAgentBinarySkipsUpdateWhenPersistFails(t *testing.T) {
	previousPersist := persistRemoteControlState
	previousUpdate := updateBinaryTo
	t.Cleanup(func() {
		persistRemoteControlState = previousPersist
		updateBinaryTo = previousUpdate
	})
	persistRemoteControlState = func(string) error { return errors.New("persist failed") }
	updated := false
	updateBinaryTo = func(*selfupdate.Updater, *selfupdate.Release, string) error {
		updated = true
		return nil
	}
	if err := replaceAgentBinary(nil, &selfupdate.Release{}, "Lite-Plus-agent"); err == nil {
		t.Fatal("expected persist failure")
	}
	if updated {
		t.Fatal("binary must not be replaced when remote-control state cannot be persisted")
	}
}
