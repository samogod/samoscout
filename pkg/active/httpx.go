package active

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type HttpxResult struct {
	Host          string   `json:"host"`
	URL           string   `json:"url"`
	StatusCode    int      `json:"status_code"`
	Title         string   `json:"title"`
	Technologies  []string `json:"technologies"`
	WebServer     string   `json:"webserver"`
	ContentType   string   `json:"content_type"`
	ContentLength int      `json:"content_length"`
}

func getHttpxPath() (string, error) {
	if path, err := exec.LookPath("httpx"); err == nil {
		return path, nil
	}

	goBinPaths := []string{}

	if gopath := os.Getenv("GOPATH"); gopath != "" {
		goBinPaths = append(goBinPaths, filepath.Join(gopath, "bin", "httpx"))
	}

	if home := os.Getenv("HOME"); home != "" {
		goBinPaths = append(goBinPaths, filepath.Join(home, "go", "bin", "httpx"))
	}

	for _, path := range goBinPaths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("httpx not found")
}

func EnsureHttpx(verbose bool) error {
	if path, err := getHttpxPath(); err == nil {
		if verbose {
			fmt.Printf("[DBG] httpx binary found: %s\n", path)
		}
		return nil
	}

	if verbose {
		fmt.Println("[DBG] httpx not found, installing via go install...")
	}

	cmd := exec.Command("go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install httpx: %w", err)
	}

	if path, err := getHttpxPath(); err == nil {
		fmt.Printf("[ACTIVE] httpx installed successfully: %s\n", path)
	} else {
		fmt.Println("[ACTIVE] httpx installed successfully")
	}

	return nil
}

func RunHttpx(subdomainFile, outputFile string, verbose bool) ([]HttpxResult, error) {
	httpxPath, err := getHttpxPath()
	if err != nil {
		return nil, fmt.Errorf("httpx executable not found: %w", err)
	}

	absSubdomainFile, err := filepath.Abs(subdomainFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for subdomain file: %w", err)
	}

	absOutputFile, err := filepath.Abs(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for output file: %w", err)
	}

	args := []string{
		"-l", absSubdomainFile,
		"-status-code",
		"-title",
		"-tech-detect",
		"-web-server",
		"-content-type",
		"-content-length",
		"-follow-redirects",
		"-random-agent",
		"-silent",
		"-no-color",
		"-threads", "50",
		"-timeout", "10",
		"-retries", "1",
		"-json",
		"-o", absOutputFile,
	}

	if verbose {
		fmt.Printf("[DBG] executing: %s %s\n", httpxPath, strings.Join(args, " "))
	}

	cmd := exec.Command(httpxPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("httpx failed: %w", err)
	}

	results, err := readHttpxResults(absOutputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read httpx output: %w", err)
	}

	return results, nil
}

func readHttpxResults(filePath string) ([]HttpxResult, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var results []HttpxResult
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var result HttpxResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}

		results = append(results, result)
	}

	return results, scanner.Err()
}

func readSimpleList(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}

	return lines, scanner.Err()
}

func ProbeHTTPSimple(subdomains []string, outputDir string, verbose bool) ([]string, error) {
	if err := EnsureHttpx(verbose); err != nil {
		return nil, fmt.Errorf("httpx setup failed: %w", err)
	}

	subdomainFile := filepath.Join(outputDir, "final_subdomains.txt")
	if err := writeSubdomainsToFile(subdomains, subdomainFile); err != nil {
		return nil, fmt.Errorf("failed to write subdomains for httpx: %w", err)
	}

	fmt.Printf("[ACTIVE] Probing HTTP/HTTPS on %d subdomains\n", len(subdomains))

	outputFile := filepath.Join(outputDir, "active_web_services.txt")

	httpxPath, err := getHttpxPath()
	if err != nil {
		return nil, fmt.Errorf("httpx executable not found: %w", err)
	}

	args := []string{
		"-l", subdomainFile,
		"-silent",
		"-no-color",
		"-threads", "100",
		"-timeout", "5",
		"-retries", "1",
		"-random-agent",
		"-o", outputFile,
	}

	if verbose {
		fmt.Printf("[DBG] executing: %s %s\n", httpxPath, strings.Join(args, " "))
	}

	cmd := exec.Command(httpxPath, args...)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("httpx failed: %w", err)
	}

	activeURLs, err := readSimpleList(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read httpx output: %w", err)
	}

	fmt.Printf("[ACTIVE] Found %d active web services\n", len(activeURLs))

	return activeURLs, nil
}

func ProbeHTTP(subdomains []string, outputDir string, inputFileName string, verbose bool) ([]HttpxResult, []string, error) {
	if err := EnsureHttpx(verbose); err != nil {
		return nil, nil, fmt.Errorf("httpx setup failed: %w", err)
	}

	if inputFileName == "" {
		inputFileName = "httpx_input.txt"
	}

	subdomainFile := filepath.Join(outputDir, inputFileName)
	if err := writeSubdomainsToFile(subdomains, subdomainFile); err != nil {
		return nil, nil, fmt.Errorf("failed to write subdomains for httpx: %w", err)
	}

	fmt.Printf("[ACTIVE] Starting HTTP probing: %d subdomains\n", len(subdomains))

	outputFile := filepath.Join(outputDir, strings.TrimSuffix(inputFileName, ".txt")+"_httpx_results.json")
	results, err := RunHttpx(subdomainFile, outputFile, verbose)
	if err != nil {
		return nil, nil, err
	}

	activeHosts := make([]string, 0, len(results))
	for _, result := range results {
		activeHosts = append(activeHosts, result.Host)
	}

	fmt.Printf("[ACTIVE] HTTP probing complete: %d/%d hosts are active web services\n",
		len(activeHosts), len(subdomains))

	if verbose && len(results) > 0 {
		fmt.Printf("[DBG] Active web services summary:\n")
		statusCounts := make(map[int]int)
		for _, result := range results {
			statusCounts[result.StatusCode]++
		}
		for status, count := range statusCounts {
			fmt.Printf("[DBG]   HTTP %d: %d hosts\n", status, count)
		}
	}

	return results, activeHosts, nil
}
