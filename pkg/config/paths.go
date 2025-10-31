package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// windows: C:\Users\{user}\AppData\Roaming\samoscout
// macOS: ~/Library/Application Support/samoscout
// linux: ~/.config/samoscout
func GetConfigDir() string {
	var configDir string

	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				panic(fmt.Sprintf("failed to get user home directory: %v", err))
			}
			appData = filepath.Join(home, "AppData", "Roaming")
		}
		configDir = filepath.Join(appData, "samoscout")

	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			panic(fmt.Sprintf("failed to get user home directory: %v", err))
		}
		configDir = filepath.Join(home, "Library", "Application Support", "samoscout")

	default:
		xdgConfig := os.Getenv("XDG_CONFIG_HOME")
		if xdgConfig == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				panic(fmt.Sprintf("failed to get user home directory: %v", err))
			}
			xdgConfig = filepath.Join(home, ".config")
		}
		configDir = filepath.Join(xdgConfig, "samoscout")
	}

	return configDir
}

// windows: C:\Users\{user}\AppData\Local\samoscout
// macOS: ~/Library/Caches/samoscout
// linux: ~/.cache/samoscout
func GetCacheDir() string {
	var cacheDir string

	switch runtime.GOOS {
	case "windows":
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				panic(fmt.Sprintf("failed to get user home directory: %v", err))
			}
			localAppData = filepath.Join(home, "AppData", "Local")
		}
		cacheDir = filepath.Join(localAppData, "samoscout")

	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			panic(fmt.Sprintf("failed to get user home directory: %v", err))
		}
		cacheDir = filepath.Join(home, "Library", "Caches", "samoscout")

	default:
		xdgCache := os.Getenv("XDG_CACHE_HOME")
		if xdgCache == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				panic(fmt.Sprintf("failed to get user home directory: %v", err))
			}
			xdgCache = filepath.Join(home, ".cache")
		}
		cacheDir = filepath.Join(xdgCache, "samoscout")
	}

	return cacheDir
}

func GetDefaultConfigPath() string {
	return filepath.Join(GetConfigDir(), "config.yaml")
}

func GetLLMCacheDir() string {
	return filepath.Join(GetCacheDir(), "llm")
}

