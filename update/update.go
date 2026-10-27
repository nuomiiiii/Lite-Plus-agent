package update

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/blang/semver"
	"github.com/nuomiiiii/lite-agent/cmd/flags"
	"github.com/nuomiiiii/lite-agent/dnsresolver"
	"github.com/nuomiiiii/lite-agent/remotecontrol"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
)

var (
	CurrentVersion string = "0.0.1.5"
	// Repo is the Plus agent GitHub release channel. Do not point at Lite-agent.
	Repo string = "nuomiiiii/Lite-Plus-agent"
)

const (
	snapshotVersionPrefix         = "Snapshot-"
	containerMarkerPath           = "/.lite-plus-agent-container"
	liteContainerMarkerPath       = "/.lite-agent-container"
	legacyContainerMarkerPath     = "/.komari-agent-container"
	releaseAssetPrefix            = "Lite-Plus-agent"
	githubAPIBaseURL          = "https://api.github.com"
	regularCheckInterval      = 6 * time.Hour
	retryCheckInterval        = 15 * time.Minute
)

type buildTrack int

const (
	stableTrack buildTrack = iota
	snapshotTrack
)

type githubRelease struct {
	TagName     string               `json:"tag_name"`
	Name        string               `json:"name"`
	Body        string               `json:"body"`
	Draft       bool                 `json:"draft"`
	Prerelease  bool                 `json:"prerelease"`
	HTMLURL     string               `json:"html_url"`
	PublishedAt time.Time            `json:"published_at"`
	Assets      []githubReleaseAsset `json:"assets"`
}

type githubReleaseAsset struct {
	ID                 int64  `json:"id"`
	Name               string `json:"name"`
	Size               int    `json:"size"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type snapshotReleaseCandidate struct {
	TagName     string
	Name        string
	Body        string
	HTMLURL     string
	PublishedAt time.Time
	Asset       githubReleaseAsset
}

type stableReleaseCandidate struct {
	Version     comparableVersion
	TagName     string
	Name        string
	Body        string
	HTMLURL     string
	PublishedAt time.Time
	Asset       githubReleaseAsset
	HasAsset    bool
}

type comparableVersion struct {
	base             semver.Version
	revision         uint64
	explicitRevision bool
}

func (version comparableVersion) String() string {
	value := version.base.String()
	if !version.explicitRevision {
		return value
	}
	core := fmt.Sprintf("%d.%d.%d", version.base.Major, version.base.Minor, version.base.Patch)
	return strings.Replace(value, core, fmt.Sprintf("%s.%d", core, version.revision), 1)
}

// parseVersion accepts standard semver and Lite's four-part Agent versions.
// Three-part versions are treated as revision zero during comparison.
func parseVersion(ver string) (comparableVersion, error) {
	ver = strings.TrimSpace(ver)
	ver = strings.TrimPrefix(ver, "v")
	ver = strings.TrimPrefix(ver, "V")

	coreEnd := len(ver)
	if index := strings.IndexAny(ver, "-+"); index >= 0 {
		coreEnd = index
	}
	core := ver[:coreEnd]
	parts := strings.Split(core, ".")
	if len(parts) != 4 {
		base, err := semver.ParseTolerant(ver)
		if err != nil {
			return comparableVersion{}, err
		}
		return comparableVersion{base: base}, nil
	}

	revision, err := strconv.ParseUint(parts[3], 10, 64)
	if err != nil {
		return comparableVersion{}, fmt.Errorf("invalid fourth version segment %q: %w", parts[3], err)
	}
	normalized := strings.Join(parts[:3], ".") + ver[coreEnd:]
	base, err := semver.ParseTolerant(normalized)
	if err != nil {
		return comparableVersion{}, err
	}
	return comparableVersion{base: base, revision: revision, explicitRevision: true}, nil
}

// BumpPatch adds one to the fourth Plus-agent segment (0.0.0.1 → 0.0.0.2).
func BumpPatch(version string) (string, error) {
	parsed, err := parseVersion(version)
	if err != nil {
		return "", err
	}
	if !parsed.explicitRevision {
		return "", fmt.Errorf("plus-agent version %q must have four numeric segments", version)
	}
	parsed.revision++
	parsed.base.Pre = nil
	parsed.base.Build = nil
	return parsed.String(), nil
}

// compareVersions keeps the historical 2.1.x same-release suffix ordering.
// For example, 2.1.62 is the second refresh of 2.1.6, while 2.1.7 is the
// next feature release. Other version lines retain standard semver ordering.
func compareVersions(left, right comparableVersion) int {
	leftBasePatch, leftRevision := versionPatchOrder(left)
	rightBasePatch, rightRevision := versionPatchOrder(right)

	leftBase := left.base
	leftBase.Patch = leftBasePatch
	rightBase := right.base
	rightBase.Patch = rightBasePatch

	if leftBase.Major != rightBase.Major {
		if leftBase.Major < rightBase.Major {
			return -1
		}
		return 1
	}
	if leftBase.Minor != rightBase.Minor {
		if leftBase.Minor < rightBase.Minor {
			return -1
		}
		return 1
	}
	if leftBase.Patch != rightBase.Patch {
		if leftBase.Patch < rightBase.Patch {
			return -1
		}
		return 1
	}
	if leftRevision < rightRevision {
		return -1
	}
	if leftRevision > rightRevision {
		return 1
	}

	// The numeric portions are equal. Compare prerelease identifiers using the
	// existing semver implementation; build metadata remains non-ordering.
	leftBase.Major, leftBase.Minor, leftBase.Patch = 0, 0, 0
	rightBase.Major, rightBase.Minor, rightBase.Patch = 0, 0, 0
	return leftBase.Compare(rightBase)
}

func versionPatchOrder(version comparableVersion) (basePatch, revision uint64) {
	// This compatibility rule starts with the existing 2.1.61 release and is
	// deliberately limited to legacy three-part tags. Explicit four-part tags
	// always use their real patch and revision fields.
	if !version.explicitRevision && version.base.Major == 2 && version.base.Minor == 1 && version.base.Patch >= 61 && version.base.Patch <= 99 {
		return version.base.Patch / 10, version.base.Patch % 10
	}
	return version.base.Patch, version.revision
}

// needUpdate reports whether latest is newer than current.
func needUpdate(current, latest comparableVersion) bool {
	return compareVersions(latest, current) > 0
}

func detectBuildTrack(version string) buildTrack {
	if strings.HasPrefix(version, snapshotVersionPrefix) {
		return snapshotTrack
	}
	return stableTrack
}

func assetName(prefix, goos, goarch string) string {
	name := fmt.Sprintf("%s-%s-%s", prefix, goos, goarch)
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

func expectedAssetName(goos, goarch string) string {
	return assetName(releaseAssetPrefix, goos, goarch)
}

func expectedAssetNames(goos, goarch string) []string {
	return []string{expectedAssetName(goos, goarch)}
}

func findReleaseAsset(release githubRelease, assetNames ...string) (githubReleaseAsset, bool) {
	for _, assetName := range assetNames {
		for _, asset := range release.Assets {
			if asset.Name == assetName {
				return asset, true
			}
		}
	}
	return githubReleaseAsset{}, false
}

func selectLatestSnapshotRelease(releases []githubRelease, assetNames ...string) (snapshotReleaseCandidate, bool) {
	var latest snapshotReleaseCandidate
	found := false

	for _, release := range releases {
		if release.Draft || !release.Prerelease || !strings.HasPrefix(release.TagName, snapshotVersionPrefix) {
			continue
		}

		asset, ok := findReleaseAsset(release, assetNames...)
		if !ok {
			continue
		}

		candidate := snapshotReleaseCandidate{
			TagName:     release.TagName,
			Name:        release.Name,
			Body:        release.Body,
			HTMLURL:     release.HTMLURL,
			PublishedAt: release.PublishedAt,
			Asset:       asset,
		}

		if !found ||
			candidate.PublishedAt.After(latest.PublishedAt) ||
			(candidate.PublishedAt.Equal(latest.PublishedAt) && candidate.TagName > latest.TagName) {
			latest = candidate
			found = true
		}
	}

	return latest, found
}

func selectLatestStableRelease(releases []githubRelease, assetNames ...string) (stableReleaseCandidate, bool) {
	var latest stableReleaseCandidate
	found := false

	for _, release := range releases {
		if release.Draft || release.Prerelease {
			continue
		}

		version, err := parseVersion(strings.TrimSpace(release.TagName))
		if err != nil {
			continue
		}
		if found && compareVersions(version, latest.Version) <= 0 {
			continue
		}

		asset, hasAsset := findReleaseAsset(release, assetNames...)
		latest = stableReleaseCandidate{
			Version:     version,
			TagName:     release.TagName,
			Name:        release.Name,
			Body:        release.Body,
			HTMLURL:     release.HTMLURL,
			PublishedAt: release.PublishedAt,
			Asset:       asset,
			HasAsset:    hasAsset,
		}
		found = true
	}

	return latest, found
}

func snapshotNeedsUpdate(currentVersion string, latest snapshotReleaseCandidate) bool {
	return currentVersion != latest.TagName
}

func isContainerAgent() bool {
	for _, marker := range []string{containerMarkerPath, liteContainerMarkerPath, legacyContainerMarkerPath} {
		if _, err := os.Stat(marker); err == nil {
			return true
		}
	}
	return false
}

func listUpdateReleases() (owner, repo string, releases []githubRelease, err error) {
	owner, repo, err = splitRepoSlug(Repo)
	if err != nil {
		return "", "", nil, err
	}
	releases, err = listGitHubReleases(owner, repo)
	if err != nil {
		return "", "", nil, err
	}
	return owner, repo, releases, nil
}

func splitRepoSlug(slug string) (string, string, error) {
	parts := strings.Split(slug, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid repo slug %q, expected owner/name", slug)
	}
	return parts[0], parts[1], nil
}

func listGitHubReleases(owner, repo string) ([]githubRelease, error) {
	var releases []githubRelease

	for page := 1; ; page++ {
		endpoint := fmt.Sprintf(
			"%s/repos/%s/%s/releases?per_page=100&page=%d",
			githubAPIBaseURL,
			url.PathEscape(owner),
			url.PathEscape(repo),
			page,
		)
		req, err := http.NewRequest(http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create GitHub releases request: %w", err)
		}

		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("User-Agent", "Lite-Plus-agent")
		if token := os.Getenv("GITHUB_TOKEN"); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to list GitHub releases: %w", err)
		}

		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			return nil, fmt.Errorf("GitHub releases API returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}

		var pageReleases []githubRelease
		if err := json.NewDecoder(resp.Body).Decode(&pageReleases); err != nil {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("failed to decode GitHub releases response: %w", err)
		}
		_ = resp.Body.Close()

		releases = append(releases, pageReleases...)
		if len(pageReleases) < 100 {
			return releases, nil
		}
	}
}

func currentExecutablePath() (string, error) {
	cmdPath, err := os.Executable()
	if err != nil {
		return "", err
	}
	if runtime.GOOS == "windows" && !strings.HasSuffix(cmdPath, ".exe") {
		cmdPath += ".exe"
	}

	stat, err := os.Lstat(cmdPath)
	if err != nil {
		return "", fmt.Errorf("failed to stat %q: %w", cmdPath, err)
	}
	if stat.Mode()&os.ModeSymlink != 0 {
		resolved, err := filepath.EvalSymlinks(cmdPath)
		if err != nil {
			return "", fmt.Errorf("failed to resolve symlink %q for executable: %w", cmdPath, err)
		}
		cmdPath = resolved
	}

	return cmdPath, nil
}

func selfUpdateReleaseFromSnapshot(owner, repo string, candidate snapshotReleaseCandidate) *selfupdate.Release {
	publishedAt := candidate.PublishedAt
	return &selfupdate.Release{
		Version:           semver.Version{},
		AssetURL:          candidate.Asset.BrowserDownloadURL,
		AssetByteSize:     candidate.Asset.Size,
		AssetID:           candidate.Asset.ID,
		ValidationAssetID: -1,
		URL:               candidate.HTMLURL,
		ReleaseNotes:      candidate.Body,
		Name:              candidate.Name,
		PublishedAt:       &publishedAt,
		RepoOwner:         owner,
		RepoName:          repo,
	}
}

func selfUpdateReleaseFromStable(owner, repo string, candidate stableReleaseCandidate) *selfupdate.Release {
	publishedAt := candidate.PublishedAt
	return &selfupdate.Release{
		Version:           candidate.Version.base,
		AssetURL:          candidate.Asset.BrowserDownloadURL,
		AssetByteSize:     candidate.Asset.Size,
		AssetID:           candidate.Asset.ID,
		ValidationAssetID: -1,
		URL:               candidate.HTMLURL,
		ReleaseNotes:      candidate.Body,
		Name:              candidate.Name,
		PublishedAt:       &publishedAt,
		RepoOwner:         owner,
		RepoName:          repo,
	}
}

func nextCheckDelay(lastCheckFailed bool) time.Duration {
	if lastCheckFailed {
		return retryCheckInterval
	}
	return regularCheckInterval
}

func DoUpdateWorks(initialCheckFailed bool) {
	lastCheckFailed := initialCheckFailed
	for {
		timer := time.NewTimer(nextCheckDelay(lastCheckFailed))
		<-timer.C

		if err := CheckAndUpdate(); err != nil {
			log.Println("[ERROR]", err)
			lastCheckFailed = true
			continue
		}
		lastCheckFailed = false
	}
}

func checkAndUpdateStable(currentVersion comparableVersion, updater *selfupdate.Updater) error {
	owner, repo, releases, err := listUpdateReleases()
	if err != nil {
		return err
	}

	assetNames := expectedAssetNames(runtime.GOOS, runtime.GOARCH)
	latest, found := selectLatestStableRelease(releases, assetNames...)
	if !found || !needUpdate(currentVersion, latest.Version) {
		log.Println("Current version is the latest:", CurrentVersion)
		return nil
	}
	if !latest.HasAsset {
		return fmt.Errorf("release %s is available, but asset %s is not ready; retry in %s", latest.TagName, strings.Join(assetNames, " or "), retryCheckInterval)
	}

	cmdPath, err := currentExecutablePath()
	if err != nil {
		return fmt.Errorf("failed to resolve current executable path: %w", err)
	}

	log.Printf("Will update %s from %s to %s\n", cmdPath, CurrentVersion, latest.TagName)
	if err := replaceAgentBinary(updater, selfUpdateReleaseFromStable(owner, repo, latest), cmdPath); err != nil {
		return fmt.Errorf("failed to update to stable release %s: %w", latest.TagName, err)
	}
	// Default is installed as a service, so don't automatically restart
	//execPath, err := os.Executable()
	//if err != nil {
	//	return fmt.Errorf("failed to get current executable path: %v", err)
	//}

	// _, err = os.StartProcess(execPath, os.Args, &os.ProcAttr{
	// 	Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	// })
	// if err != nil {
	// 	return fmt.Errorf("failed to restart program: %v", err)
	// }
	log.Printf("Successfully updated to version %s\n", latest.Version)
	os.Exit(42)
	return nil
}

func checkAndUpdateSnapshot(updater *selfupdate.Updater) error {
	if isContainerAgent() {
		log.Println("Snapshot agent is running in a container; skip binary self-update. Refresh the ghcr.io image tagged 'snapshot' instead.")
		return nil
	}

	owner, repo, releases, err := listUpdateReleases()
	if err != nil {
		return err
	}

	assetNames := expectedAssetNames(runtime.GOOS, runtime.GOARCH)
	latest, found := selectLatestSnapshotRelease(releases, assetNames...)
	if !found {
		log.Printf("No suitable snapshot release asset was found for %s. Current snapshot is considered up-to-date.", strings.Join(assetNames, " or "))
		return nil
	}

	if !snapshotNeedsUpdate(CurrentVersion, latest) {
		log.Println("Current snapshot version is the latest:", CurrentVersion)
		return nil
	}

	cmdPath, err := currentExecutablePath()
	if err != nil {
		return fmt.Errorf("failed to resolve current executable path: %w", err)
	}

	log.Printf("Will update %s from snapshot %s to %s\n", cmdPath, CurrentVersion, latest.TagName)
	if err := replaceAgentBinary(updater, selfUpdateReleaseFromSnapshot(owner, repo, latest), cmdPath); err != nil {
		return fmt.Errorf("failed to update to snapshot %s: %w", latest.TagName, err)
	}

	log.Printf("Successfully updated to snapshot version %s\n", latest.TagName)
	os.Exit(42)
	return nil
}

func updateChannelConfigured() bool {
	repo := strings.TrimSpace(Repo)
	if repo == "" {
		return false
	}
	switch strings.ToLower(repo) {
	case "nuomiiiii/lite-agent", "nuomiiiii/komari-agent":
		return false
	default:
		return true
	}
}

// CheckAndUpdate checks GitHub for a newer agent and applies it.
func CheckAndUpdate() error {
	if !updateChannelConfigured() {
		log.Println("Automatic updates are disabled: Plus update channel is not configured.")
		return nil
	}
	log.Println("Checking update...")

	http.DefaultClient = dnsresolver.GetHTTPClient(60 * time.Second)
	updater, err := selfupdate.NewUpdater(selfupdate.Config{})
	if err != nil {
		return fmt.Errorf("failed to create updater: %v", err)
	}

	if detectBuildTrack(CurrentVersion) == snapshotTrack {
		return checkAndUpdateSnapshot(updater)
	}

	currentVersion, err := parseVersion(CurrentVersion)
	if err != nil {
		return fmt.Errorf("failed to parse current version: %v", err)
	}

	return checkAndUpdateStable(currentVersion, updater)
}

func persistRemoteControlBeforeReplace(cmdPath string) error {
	return remotecontrol.WriteAtomic(remotecontrol.PathForExecutable(cmdPath), flags_pkg.RemoteControlEnabled())
}

var (
	persistRemoteControlState = persistRemoteControlBeforeReplace
	updateBinaryTo            = func(updater *selfupdate.Updater, rel *selfupdate.Release, cmdPath string) error {
		return updater.UpdateTo(rel, cmdPath)
	}
)

func replaceAgentBinary(updater *selfupdate.Updater, rel *selfupdate.Release, cmdPath string) error {
	if err := persistRemoteControlState(cmdPath); err != nil {
		return fmt.Errorf("persist remote-control state before replacing binary: %w", err)
	}
	return updateBinaryTo(updater, rel, cmdPath)
}
