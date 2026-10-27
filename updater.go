package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var Version = "v1.0.0"

const (
	GitHubRepo   = "roleplay-utilities/mu-auth-matrix-sidecar"
	ServiceName  = "mu-sidecar"
	ServiceDesc  = "MU Auth Matrix Sidecar Utility"
)

type GitHubRelease struct {
	TagName    string `json:"tag_name"`
	Name       string `json:"name"`
	Body       string `json:"body"`
	Prerelease bool   `json:"prerelease"`
	Assets     []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

type UpdateSettings struct {
	Prereleases bool `json:"prereleases"`
	AutoRestart bool `json:"auto_restart"`
}

// ==========================================
// INSTALLATION & SERVICE REGISTRATION
// ==========================================

func getTargetInstallPath() string {
	switch runtime.GOOS {
	case "windows":
		programFiles := os.Getenv("ProgramFiles")
		if programFiles == "" {
			programFiles = "C:\\Program Files"
		}
		return filepath.Join(programFiles, "MuSidecar", "mu-sidecar.exe")
	case "darwin":
		return filepath.Join("/usr/local/bin", "mu-sidecar")
	default:
		return filepath.Join("/opt", "mu-sidecar", "mu-sidecar")
	}
}

func EnsureInstalledAndRegistered() {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return
	}
	exPath, err := getExecutablePath()
	if err != nil {
		return
	}

	targetPath := getTargetInstallPath()
	targetDir := filepath.Dir(targetPath)

	// If we are not running from the official installation path, bootstrap install
	if !strings.EqualFold(exPath, targetPath) {
		fmt.Printf("[SETUP] Installing sidecar to standard path: %s\n", targetPath)

		if err := os.MkdirAll(targetDir, 0755); err != nil {
			fmt.Printf("[SETUP ERROR] Failed to create installation directory: %v\n", err)
			return
		}

		// Copy binary
		if err := copyFile(exPath, targetPath); err != nil {
			fmt.Printf("[SETUP ERROR] Failed to copy binary: %v\n", err)
			return
		}

		// Copy companion files (.env and settings) if they exist in the source directory
		sourceDir := filepath.Dir(exPath)
		for _, filename := range []string{".env", "sidecar_settings.json"} {
			srcFile := filepath.Join(sourceDir, filename)
			if _, err := os.Stat(srcFile); err == nil {
				dstFile := filepath.Join(targetDir, filename)
				_ = copyFile(srcFile, dstFile)
				fmt.Printf("[SETUP] Migrated companion file: %s\n", filename)
			}
		}

		if runtime.GOOS != "windows" {
			_ = os.Chmod(targetPath, 0755)
		}

		// Register system service
		registerSystemService(targetPath)

		// Launch the newly installed binary and exit this instance
		fmt.Println("[SETUP] Installation complete. Launching from permanent location...")
		cmd := exec.Command(targetPath, os.Args[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		_ = cmd.Start()
		os.Exit(0)
	}
}

func registerSystemService(binPath string) {
	switch runtime.GOOS {
	case "windows":
		// Register a Windows Scheduled Task to run at system startup as SYSTEM with highest privileges.
		// This bypasses the SCM service protocol (preventing Error 1053) while acting like a background service.
		taskName := ServiceName
		
		// Delete existing task if it exists to allow clean updates/re-registrations
		_ = exec.Command("schtasks", "/delete", "/tn", taskName, "/f").Run()

		// Create the startup task
		cmd := exec.Command(
			"schtasks", "/create",
			"/tn", taskName,
			"/tr", fmt.Sprintf("\"%s\"", binPath),
			"/sc", "ONSTART",
			"/ru", "SYSTEM",
			"/rl", "HIGHEST",
			"/f",
		)

		if err := cmd.Run(); err == nil {
			// Start the task immediately
			_ = exec.Command("schtasks", "/run", "/tn", taskName).Run()
			fmt.Println("[SETUP] Windows background startup task registered and started successfully.")
		} else {
			fmt.Println("[SETUP] Note: Run as Administrator to auto-register Windows startup task.")
		}

	case "linux":
		serviceContent := fmt.Sprintf(`[Unit]
Description=%s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
`, ServiceDesc, binPath)

		serviceFilePath := fmt.Sprintf("/etc/systemd/system/%s.service", ServiceName)
		if err := os.WriteFile(serviceFilePath, []byte(serviceContent), 0644); err == nil {
			_ = exec.Command("systemctl", "daemon-reload").Run()
			_ = exec.Command("systemctl", "enable", ServiceName).Run()
			_ = exec.Command("systemctl", "start", ServiceName).Run()
			fmt.Println("[SETUP] Systemd service registered and started successfully.")
		} else {
			fmt.Println("[SETUP] Note: Run with sudo privileges to auto-register systemd service.")
		}
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

// ==========================================
// SEMVER & UPDATES
// ==========================================

type SemVer struct {
	Major      int
	Minor      int
	Patch      int
	Prerelease string
}

func parseSemVer(vStr string) (SemVer, bool) {
	vStr = strings.TrimPrefix(strings.TrimSpace(vStr), "v")
	parts := strings.SplitN(vStr, "-", 2)
	coreParts := strings.Split(parts[0], ".")
	if len(coreParts) < 3 {
		// Handle cases like v1.0 -> v1.0.0
		for len(coreParts) < 3 {
			coreParts = append(coreParts, "0")
		}
	}

	major, err1 := strconv.Atoi(coreParts[0])
	minor, err2 := strconv.Atoi(coreParts[1])
	
	// Handle non-standard pre-releases like "1.0.1a" -> split numbers and letters if needed
	patchStr := coreParts[2]
	var prerelease string
	if len(parts) > 1 {
		prerelease = parts[1]
	}

	// Clean up attached letters like "1a" -> patch 1, prerelease "a"
	var patch int
	var err3 error
	for i := len(patchStr); i > 0; i-- {
		if patch, err3 = strconv.Atoi(patchStr[:i]); err3 == nil {
			if i < len(patchStr) {
				prerelease = patchStr[i:] + (func() string {
					if prerelease != "" {
						return "." + prerelease
					}
					return ""
				}())
			}
			break
		}
	}

	if err1 != nil || err2 != nil {
		return SemVer{}, false
	}

	return SemVer{
		Major:      major,
		Minor:      minor,
		Patch:      patch,
		Prerelease: prerelease,
	}, true
}

// IsNewerVersion returns true if remoteVersion is strictly newer than currentVersion.
// Handles stable vs pre-release precedence correctly.
func IsNewerVersion(currentStr, remoteStr string) bool {
	curr, ok1 := parseSemVer(currentStr)
	rem, ok2 := parseSemVer(remoteStr)
	if !ok1 || !ok2 {
		return remoteStr != currentStr // Fallback to string comparison if parsing fails
	}

	if rem.Major != curr.Major {
		return rem.Major > curr.Major
	}
	if rem.Minor != curr.Minor {
		return rem.Minor > curr.Minor
	}
	if rem.Patch != curr.Patch {
		return rem.Patch > curr.Patch
	}

	// Pre-release evaluation rules:
	// A version with a pre-release is LOWER than the corresponding stable version (e.g. v1.0.1-alpha < v1.0.1)
	if curr.Prerelease == "" && rem.Prerelease != "" {
		return false // Remote is pre-release, current is stable -> not newer
	}
	if curr.Prerelease != "" && rem.Prerelease == "" {
		return true // Current is pre-release, remote is stable -> newer!
	}

	// If both have pre-releases, compare alphabetically/numerically
	return rem.Prerelease > curr.Prerelease
}

func getSettingsPath() string {
	ex, err := getExecutablePath()
	if err != nil {
		return "sidecar_settings.json"
	}
	return filepath.Join(filepath.Dir(ex), "sidecar_settings.json")
}

func LoadUpdateSettings() UpdateSettings {
	path := getSettingsPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return UpdateSettings{Prereleases: false, AutoRestart: true}
	}
	var s UpdateSettings
	if json.Unmarshal(data, &s) != nil {
		return UpdateSettings{Prereleases: false, AutoRestart: true}
	}
	return s
}

func CheckForUpdates() {
	settings := LoadUpdateSettings()
	release, err := fetchTargetRelease(settings.Prereleases)
	if err != nil || release.TagName == "" {
		return
	}

	// Use semantic version checking instead of blind string equality
	if !IsNewerVersion(Version, release.TagName) {
		return
	}

	fmt.Printf("\n[UPDATE AVAILABLE] A new version is available: %s (Current: %s)\n", release.TagName, Version)
	if release.Name != "" {
		fmt.Printf("Title: %s\n", release.Name)
	}
	if release.Body != "" {
		fmt.Println("--- Changelog ---")
		fmt.Println(release.Body)
		fmt.Println("-----------------")
	}

	if runtime.GOOS == "windows" {
		if err := applyWindowsUpdate(release, settings.AutoRestart); err != nil {
			fmt.Printf("[UPDATE ERROR] Windows update failed: %v\n", err)
		}
	} else {
		if err := applyUnixUpdate(release, settings.AutoRestart); err != nil {
			fmt.Printf("[UPDATE ERROR] Unix update failed: %v\n", err)
		}
	}
}

func fetchTargetRelease(includePrereleases bool) (*GitHubRelease, error) {
	client := &http.Client{Timeout: 8 * time.Second}
	var endpoint string
	if includePrereleases {
		endpoint = fmt.Sprintf("https://api.github.com/repos/%s/releases?per_page=5", GitHubRepo)
	} else {
		endpoint = fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", GitHubRepo)
	}

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mu-Sidecar-AutoUpdater")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github API status: %d", resp.StatusCode)
	}

	bodyBytes, _ := io.ReadAll(resp.Body)

	if includePrereleases {
		var rels []GitHubRelease
		if json.Unmarshal(bodyBytes, &rels) != nil || len(rels) == 0 {
			return nil, fmt.Errorf("no releases found")
		}
		return &rels[0], nil
	} else {
		var rel GitHubRelease
		if json.Unmarshal(bodyBytes, &rel) != nil {
			return nil, fmt.Errorf("failed to parse release")
		}
		return &rel, nil
	}
}

func applyUnixUpdate(release *GitHubRelease, autoRestart bool) error {
	targetAsset := fmt.Sprintf("sidecar-%s-%s", runtime.GOOS, runtime.GOARCH)
	downloadURL := findMatchingAsset(release, targetAsset)
	if downloadURL == "" {
		return fmt.Errorf("no matching binary found for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	exPath, err := getExecutablePath()
	if err != nil {
		return err
	}

	tmpFile := exPath + ".new"
	if err := downloadFile(tmpFile, downloadURL); err != nil {
		return err
	}

	if err := os.Chmod(tmpFile, 0755); err != nil {
		os.Remove(tmpFile)
		return err
	}

	if err := os.Rename(tmpFile, exPath); err != nil {
		os.Remove(tmpFile)
		return err
	}

	if !autoRestart {
		fmt.Println("[UPDATE] Update downloaded and installed successfully. Please restart the sidecar manually.")
		return nil
	}

	fmt.Println("[UPDATE] Update applied successfully. Restarting service...")
	restartServiceOrReexec(exPath)
	return nil
}

func applyWindowsUpdate(release *GitHubRelease, autoRestart bool) error {
	targetAsset := fmt.Sprintf("sidecar-windows-%s.exe", runtime.GOARCH)
	downloadURL := findMatchingAsset(release, targetAsset)
	if downloadURL == "" {
		return fmt.Errorf("no matching Windows binary found for %s", runtime.GOARCH)
	}

	exPath, err := getExecutablePath()
	if err != nil {
		return err
	}

	tmpFile := exPath + ".new"
	if err := downloadFile(tmpFile, downloadURL); err != nil {
		return err
	}

	if !autoRestart {
		altFile := exPath + ".update"
		_ = os.Rename(tmpFile, altFile)
		fmt.Printf("[UPDATE] New version downloaded to %s.\n", altFile)
		return nil
	}

	batPath := filepath.Join(filepath.Dir(exPath), "update_swapper.bat")
	batScript := fmt.Sprintf(`@echo off
timeout /t 2 /nobreak > nul
move /y "%s" "%s"
sc start %s > nul 2>&1
if %%errorlevel%% neq 0 start "" "%s"
del "%%~f0"
`, tmpFile, exPath, ServiceName, exPath)

	fnErr := os.WriteFile(batPath, []byte(batScript), 0644)
	if fnErr != nil {
		os.Remove(tmpFile)
		return fnErr
	}

	fmt.Println("[UPDATE] Update downloaded. Swapping binary and restarting service...")
	cmd := exec.Command("cmd.exe", "/c", batPath)
	if err := cmd.Start(); err != nil {
		return err
	}

	os.Exit(0)
	return nil
}

func getExecutablePath() (string, error) {
	ex, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Abs(ex)
}

func findMatchingAsset(release *GitHubRelease, target string) string {
	for _, asset := range release.Assets {
		if strings.EqualFold(asset.Name, target) || strings.HasPrefix(asset.Name, target) {
			return asset.BrowserDownloadURL
		}
	}
	if len(release.Assets) > 0 {
		return release.Assets[0].BrowserDownloadURL
	}
	return ""
}

func downloadFile(filepath string, url string) error {
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	_, err = io.Copy(out, resp.Body)
	return err
}

func restartServiceOrReexec(exPath string) {
	if runtime.GOOS == "windows" {
		// Restart the scheduled task
		_ = exec.Command("schtasks", "/run", "/tn", ServiceName).Run()
		os.Exit(0)
	}
	if runtime.GOOS == "linux" {
		if err := exec.Command("systemctl", "restart", ServiceName).Run(); err == nil {
			os.Exit(0)
		}
	}
	if runtime.GOOS == "darwin" {
		if err := exec.Command("launchctl", "kickstart", "-k", "gui/"+fmt.Sprint(os.Getuid())+"/"+ServiceName).Run(); err == nil {
			os.Exit(0)
		}
	}
	args := os.Args
	_ = syscall.Exec(exPath, args, os.Environ())
	os.Exit(0)
}