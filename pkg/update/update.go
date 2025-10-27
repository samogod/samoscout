package update

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

const (
	GitHubAPI     = "https://api.github.com/repos/samogod/samoscout/releases/latest"
	UpdateTimeout = 30 * time.Second
)

type GitHubRelease struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	Body        string `json:"body"`
	PublishedAt string `json:"published_at"`
	Assets      []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
	} `json:"assets"`
}

func GetLatestVersion() (*GitHubRelease, error) {
	client := &http.Client{Timeout: UpdateTimeout}

	req, err := http.NewRequest("GET", GitHubAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "samoscout-updater")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch latest version: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &release, nil
}

func CompareVersions(current, latest string) bool {
	current = strings.TrimPrefix(current, "v")
	latest = strings.TrimPrefix(latest, "v")

	currentParts := strings.Split(current, ".")
	latestParts := strings.Split(latest, ".")

	for i := 0; i < 3; i++ {
		var c, l int
		if i < len(currentParts) {
			fmt.Sscanf(currentParts[i], "%d", &c)
		}
		if i < len(latestParts) {
			fmt.Sscanf(latestParts[i], "%d", &l)
		}

		if l > c {
			return true
		} else if l < c {
			return false
		}
	}

	return false
}

func GetBinaryName() string {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	var platform string
	switch goos {
	case "linux":
		platform = "linux"
	case "darwin":
		platform = "darwin"
	case "windows":
		platform = "windows"
	default:
		platform = goos
	}

	var arch string
	switch goarch {
	case "amd64":
		arch = "amd64"
	case "arm64":
		arch = "arm64"
	case "386":
		arch = "386"
	default:
		arch = goarch
	}

	binaryName := fmt.Sprintf("samoscout_%s_%s", platform, arch)
	if goos == "windows" {
		binaryName += ".exe"
	}

	return binaryName
}

func DownloadBinary(url, outputPath string, verbose bool) error {
	if verbose {
		fmt.Printf("[UPDATE] Downloading from %s\n", url)
	}

	client := &http.Client{Timeout: 5 * time.Minute}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	out, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()

	size := resp.ContentLength
	if verbose && size > 0 {
		fmt.Printf("[UPDATE] Downloading %d MB...\n", size/(1024*1024))
	}

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	if err := out.Chmod(0755); err != nil {
		return fmt.Errorf("failed to set executable permission: %w", err)
	}

	if verbose {
		fmt.Println("[UPDATE] Download complete")
	}

	return nil
}

func UpdateBinary(currentPath, newPath string, verbose bool) error {
	if verbose {
		fmt.Printf("[UPDATE] Replacing binary at %s\n", currentPath)
	}

	if err := os.Remove(currentPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove old binary: %w", err)
	}

	if err := os.Rename(newPath, currentPath); err != nil {
		return fmt.Errorf("failed to replace binary: %w", err)
	}

	return nil
}

func CheckAndUpdate(currentVersion string, verbose bool) error {
	if verbose {
		fmt.Println("[UPDATE] Checking for updates...")
	}

	release, err := GetLatestVersion()
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}

	latestVersion := release.TagName

	if verbose {
		fmt.Printf("[UPDATE] Current version: %s\n", currentVersion)
		fmt.Printf("[UPDATE] Latest version:  %s\n", latestVersion)
	}

	if !CompareVersions(currentVersion, latestVersion) {
		fmt.Printf("You are already running the latest version (%s)\n", currentVersion)
		return nil
	}

	fmt.Printf("New version available: %s -> %s\n", currentVersion, latestVersion)
	fmt.Println()

	binaryName := GetBinaryName()
	var downloadURL string

	for _, asset := range release.Assets {
		if asset.Name == binaryName {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}

	if downloadURL == "" {
		return fmt.Errorf("no binary found for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	tempPath := execPath + ".new"

	fmt.Println("Downloading update...")
	if err := DownloadBinary(downloadURL, tempPath, verbose); err != nil {
		os.Remove(tempPath)
		return err
	}

	fmt.Println("Installing update...")
	if err := UpdateBinary(execPath, tempPath, verbose); err != nil {
		os.Remove(tempPath)
		return err
	}

	fmt.Printf("\n✓ Successfully updated to version %s\n", latestVersion)
	fmt.Println("Please restart samoscout to use the new version")

	return nil
}
