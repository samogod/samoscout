package active

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	ResolverTrickest        = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
	ResolverTrickestTrusted = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt"
	ResolverPublicDNS       = "https://public-dns.info/nameservers.txt"
)

func DownloadResolvers(outputDir string, verbose bool) (string, string, error) {
	normalResolverFile := filepath.Join(outputDir, "resolvers.txt")
	trustedResolverFile := filepath.Join(outputDir, "resolvers_trusted.txt")

	normalExists := isResolverFileFresh(normalResolverFile)
	trustedExists := isResolverFileFresh(trustedResolverFile)

	if normalExists && trustedExists {
		if verbose {
			fmt.Println("[DBG] using cached resolver files (fresh within 24h)")
		}
		return normalResolverFile, trustedResolverFile, nil
	}

	if verbose {
		fmt.Println("[DBG] resolver cache expired or missing, downloading fresh resolvers...")
	}

	normalURLs := []string{
		ResolverTrickest,
		ResolverPublicDNS,
	}

	var normalResolvers []string
	normalSet := make(map[string]bool)

	for i, url := range normalURLs {
		if verbose {
			fmt.Printf("[DBG] downloading normal resolver list %d/2 from %s\n", i+1, url)
		}

		resolvers, err := downloadResolverList(url)
		if err != nil {
			if verbose {
				fmt.Printf("[DBG] warning: failed to download %s: %v\n", url, err)
			}
			continue
		}

		for _, resolver := range resolvers {
			if !normalSet[resolver] {
				normalSet[resolver] = true
				normalResolvers = append(normalResolvers, resolver)
			}
		}

		if verbose {
			fmt.Printf("[DBG] downloaded %d resolvers from source %d/2\n", len(resolvers), i+1)
		}
	}

	if verbose {
		fmt.Println("[DBG] downloading trusted resolver list from trickest...")
	}

	trustedResolvers, err := downloadResolverList(ResolverTrickestTrusted)
	if err != nil {
		if verbose {
			fmt.Printf("[DBG] warning: failed to download trusted resolvers: %v\n", err)
		}
		trustedResolvers = []string{}
	} else if verbose {
		fmt.Printf("[DBG] downloaded %d trusted resolvers\n", len(trustedResolvers))
	}

	if len(normalResolvers) == 0 && len(trustedResolvers) == 0 {
		return "", "", fmt.Errorf("no resolvers downloaded from any source")
	}

	if len(normalResolvers) > 0 {
		if err := writeResolvers(normalResolvers, normalResolverFile); err != nil {
			return "", "", fmt.Errorf("failed to write normal resolvers: %w", err)
		}
		if verbose {
			fmt.Printf("[DBG] %d normal resolvers saved to %s\n", len(normalResolvers), normalResolverFile)
		}
	}

	if len(trustedResolvers) > 0 {
		if err := writeResolvers(trustedResolvers, trustedResolverFile); err != nil {
			return "", "", fmt.Errorf("failed to write trusted resolvers: %w", err)
		}
		if verbose {
			fmt.Printf("[DBG] %d trusted resolvers saved to %s\n", len(trustedResolvers), trustedResolverFile)
		}
	}

	return normalResolverFile, trustedResolverFile, nil
}

func isResolverFileFresh(filePath string) bool {
	info, err := os.Stat(filePath)
	if err != nil {
		return false
	}

	age := time.Since(info.ModTime())
	return age < 24*time.Hour
}

func downloadResolverList(url string) ([]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var resolvers []string
	scanner := bufio.NewScanner(resp.Body)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if isValidResolver(line) {
			resolvers = append(resolvers, line)
		}
	}

	return resolvers, scanner.Err()
}

func isValidResolver(resolver string) bool {
	if resolver == "" {
		return false
	}

	for _, char := range resolver {
		if !((char >= '0' && char <= '9') || char == '.' || char == ':') {
			return false
		}
	}

	return true
}

func writeResolvers(resolvers []string, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, resolver := range resolvers {
		if _, err := writer.WriteString(resolver + "\n"); err != nil {
			return err
		}
	}

	return writer.Flush()
}
