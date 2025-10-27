package active

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	Six2dezWordlistURL             = "https://gist.githubusercontent.com/six2dez/a307a04a222fab5a57466c51e1569acf/raw"
	TrickestInventoryLevel2URL     = "https://raw.githubusercontent.com/trickest/wordlists/main/inventory/levels/level2.txt"
	TrickestInventoryLevel3URL     = "https://raw.githubusercontent.com/trickest/wordlists/main/inventory/levels/level3.txt"
	TrickestInventoryLevel4PlusURL = "https://raw.githubusercontent.com/trickest/wordlists/main/inventory/levels/levels4plus.txt"
	TrickestCloudLevel2URL         = "https://raw.githubusercontent.com/trickest/wordlists/main/cloud/levels/level2.txt"
	TrickestCloudLevel3URL         = "https://raw.githubusercontent.com/trickest/wordlists/main/cloud/levels/level3.txt"
	TrickestCloudLevel4PlusURL     = "https://raw.githubusercontent.com/trickest/wordlists/main/cloud/levels/levels4plus.txt"
)

func DownloadSix2dezWordlist(outputPath string) error {
	if _, err := os.Stat(outputPath); err == nil {
		return nil
	}

	resp, err := http.Get(Six2dezWordlistURL)
	if err != nil {
		return fmt.Errorf("failed to download wordlist: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status: %d", resp.StatusCode)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	if _, err := io.Copy(file, resp.Body); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

func CombineWordlists(wordlists ...[]string) []string {
	seen := make(map[string]bool)
	var combined []string

	for _, wordlist := range wordlists {
		for _, word := range wordlist {
			if !seen[word] && word != "" {
				seen[word] = true
				combined = append(combined, word)
			}
		}
	}

	return combined
}

func DownloadTrickestWordlist(url, outputPath string) error {
	if _, err := os.Stat(outputPath); err == nil {
		return nil
	}

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download wordlist from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status: %d", resp.StatusCode)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	if _, err := io.Copy(file, resp.Body); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

func MergeWordlistFiles(file1, file2, outputFile string) error {
	seen := make(map[string]bool)
	var lines []string

	for _, filePath := range []string{file1, file2} {
		file, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open %s: %w", filePath, err)
		}

		contentBytes, err := io.ReadAll(file)
		file.Close()

		if err != nil {
			return fmt.Errorf("failed to read %s: %w", filePath, err)
		}

		content := string(contentBytes)
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !seen[line] {
				seen[line] = true
				lines = append(lines, line)
			}
		}
	}

	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	for _, line := range lines {
		if _, err := outFile.WriteString(line + "\n"); err != nil {
			return fmt.Errorf("failed to write line: %w", err)
		}
	}

	return nil
}

func DownloadAndMergeTrickestWordlists(outputDir string, verbose bool) (level2, level3, level4plus string, err error) {
	if verbose {
		fmt.Println("[DBG] downloading Trickest wordlists...")
	}

	invLevel2 := filepath.Join(outputDir, "trickest_inventory_level2.txt")
	invLevel3 := filepath.Join(outputDir, "trickest_inventory_level3.txt")
	invLevel4Plus := filepath.Join(outputDir, "trickest_inventory_level4plus.txt")
	cloudLevel2 := filepath.Join(outputDir, "trickest_cloud_level2.txt")
	cloudLevel3 := filepath.Join(outputDir, "trickest_cloud_level3.txt")
	cloudLevel4Plus := filepath.Join(outputDir, "trickest_cloud_level4plus.txt")

	downloads := []struct {
		url  string
		path string
		name string
	}{
		{TrickestInventoryLevel2URL, invLevel2, "inventory level2"},
		{TrickestInventoryLevel3URL, invLevel3, "inventory level3"},
		{TrickestInventoryLevel4PlusURL, invLevel4Plus, "inventory level4plus"},
		{TrickestCloudLevel2URL, cloudLevel2, "cloud level2"},
		{TrickestCloudLevel3URL, cloudLevel3, "cloud level3"},
		{TrickestCloudLevel4PlusURL, cloudLevel4Plus, "cloud level4plus"},
	}

	for _, dl := range downloads {
		if verbose {
			fmt.Printf("[DBG] downloading %s...\n", dl.name)
		}
		if err := DownloadTrickestWordlist(dl.url, dl.path); err != nil {
			return "", "", "", fmt.Errorf("failed to download %s: %w", dl.name, err)
		}
	}

	level2 = filepath.Join(outputDir, "trickest_level2_merged.txt")
	level3 = filepath.Join(outputDir, "trickest_level3_merged.txt")
	level4plus = filepath.Join(outputDir, "trickest_level4plus_merged.txt")

	if verbose {
		fmt.Println("[DBG] merging wordlists...")
	}

	if err := MergeWordlistFiles(invLevel2, cloudLevel2, level2); err != nil {
		return "", "", "", fmt.Errorf("failed to merge level2: %w", err)
	}
	if err := MergeWordlistFiles(invLevel3, cloudLevel3, level3); err != nil {
		return "", "", "", fmt.Errorf("failed to merge level3: %w", err)
	}
	if err := MergeWordlistFiles(invLevel4Plus, cloudLevel4Plus, level4plus); err != nil {
		return "", "", "", fmt.Errorf("failed to merge level4plus: %w", err)
	}

	if verbose {
		fmt.Println("[DBG] wordlist merge complete")
	}

	return level2, level3, level4plus, nil
}
