package active

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func getPureDnsPath() (string, error) {
	if path, err := exec.LookPath("puredns"); err == nil {
		return path, nil
	}

	goBinPaths := []string{}

	if gopath := os.Getenv("GOPATH"); gopath != "" {
		goBinPaths = append(goBinPaths, filepath.Join(gopath, "bin", "puredns"))
	}

	if home := os.Getenv("HOME"); home != "" {
		goBinPaths = append(goBinPaths, filepath.Join(home, "go", "bin", "puredns"))
	}

	for _, path := range goBinPaths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("puredns not found")
}

func EnsurePureDns(verbose bool) error {
	if path, err := getPureDnsPath(); err == nil {
		if verbose {
			fmt.Printf("[DBG] puredns binary found: %s\n", path)
		}
		return nil
	}

	if verbose {
		fmt.Println("[DBG] puredns not found, installing via go install...")
	}

	cmd := exec.Command("go", "install", "github.com/d3mondev/puredns/v2@latest")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install puredns: %w", err)
	}

	if path, err := getPureDnsPath(); err == nil {
		fmt.Printf("[ACTIVE] puredns installed successfully: %s\n", path)
	} else {
		fmt.Println("[ACTIVE] puredns installed successfully")
	}

	return nil
}

func RunPureDns(subdomainFile, resolverFile, outputFile, domain string, verbose bool) ([]string, error) {
	purednsPath, err := getPureDnsPath()
	if err != nil {
		return nil, fmt.Errorf("puredns executable not found: %w", err)
	}

	absSubdomainFile, err := filepath.Abs(subdomainFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for subdomain file: %w", err)
	}

	absResolverFile, err := filepath.Abs(resolverFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for resolver file: %w", err)
	}

	absOutputFile, err := filepath.Abs(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for output file: %w", err)
	}

	trustedResolverFile := absResolverFile

	args := []string{
		"resolve",
		absSubdomainFile,
		"-w", absOutputFile,
		"-r", absResolverFile,
		"--resolvers-trusted", trustedResolverFile,
		"-l", "100",
		"--rate-limit-trusted", "100",
		"--wildcard-tests", "30",
		"--wildcard-batch", "1000000",
	}

	if verbose {
		fmt.Printf("[DBG] executing: %s %s\n", purednsPath, strings.Join(args, " "))
	}

	cmd := exec.Command(purednsPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("puredns failed: %w", err)
	}

	resolvedSubdomains, err := readResolvedSubdomains(absOutputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read puredns output: %w", err)
	}

	return resolvedSubdomains, nil
}

func RunPureDnsWithTrusted(subdomainFile, normalResolverFile, trustedResolverFile, outputFile, domain string, verbose bool) ([]string, error) {
	purednsPath, err := getPureDnsPath()
	if err != nil {
		return nil, fmt.Errorf("puredns executable not found: %w", err)
	}

	absSubdomainFile, err := filepath.Abs(subdomainFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for subdomain file: %w", err)
	}

	absNormalResolverFile, err := filepath.Abs(normalResolverFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for normal resolver file: %w", err)
	}

	absTrustedResolverFile, err := filepath.Abs(trustedResolverFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for trusted resolver file: %w", err)
	}

	absOutputFile, err := filepath.Abs(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for output file: %w", err)
	}

	args := []string{
		"resolve",
		absSubdomainFile,
		"-w", absOutputFile,
		"-r", absNormalResolverFile,
		"--resolvers-trusted", absTrustedResolverFile,
		"-l", "100",
		"--rate-limit-trusted", "100",
		"--wildcard-tests", "30",
		"--wildcard-batch", "1000000",
	}

	if verbose {
		fmt.Printf("[DBG] executing: %s %s\n", purednsPath, strings.Join(args, " "))
	}

	cmd := exec.Command(purednsPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("puredns failed: %w", err)
	}

	resolvedSubdomains, err := readResolvedSubdomains(absOutputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read puredns output: %w", err)
	}

	return resolvedSubdomains, nil
}

func readResolvedSubdomains(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var subdomains []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			subdomains = append(subdomains, line)
		}
	}

	return subdomains, scanner.Err()
}

func ResolveDNS(subdomains []string, outputDir string, domain string, verbose bool) ([]string, error) {
	if err := EnsurePureDns(verbose); err != nil {
		return nil, fmt.Errorf("puredns setup failed: %w", err)
	}

	if verbose {
		fmt.Println("[DBG] preparing dns resolvers...")
	}
	normalResolverFile, trustedResolverFile, err := DownloadResolvers(outputDir, verbose)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare resolvers: %w", err)
	}

	subdomainFile := filepath.Join(outputDir, "all_subdomains.txt")
	if err := writeSubdomainsToFile(subdomains, subdomainFile); err != nil {
		return nil, fmt.Errorf("failed to write subdomains: %w", err)
	}

	fmt.Printf("[ACTIVE] Starting DNS resolution: %d subdomains\n", len(subdomains))

	outputFile := filepath.Join(outputDir, "resolved_subdomains.txt")
	resolvedSubdomains, err := RunPureDnsWithTrusted(subdomainFile, normalResolverFile, trustedResolverFile, outputFile, domain, verbose)
	if err != nil {
		return nil, err
	}

	fmt.Printf("[ACTIVE] DNS resolution complete: %d/%d subdomains resolved\n",
		len(resolvedSubdomains), len(subdomains))

	return resolvedSubdomains, nil
}

func RunPurednsBruteforce(wordlistFile string, domains []string, normalResolver, trustedResolver, outputDir, domain string, verbose bool) ([]string, error) {
	purednsPath, err := getPureDnsPath()
	if err != nil {
		return nil, fmt.Errorf("puredns executable not found: %w", err)
	}

	domainsFile := filepath.Join(outputDir, "dsieve_domains_temp.txt")
	if err := writeSubdomainsToFile(domains, domainsFile); err != nil {
		return nil, fmt.Errorf("failed to write domains file: %w", err)
	}

	outputFile := filepath.Join(outputDir, fmt.Sprintf("bruteforce_%s_output.txt", filepath.Base(wordlistFile)))

	absWordlistFile, err := filepath.Abs(wordlistFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for wordlist: %w", err)
	}

	absDomainsFile, err := filepath.Abs(domainsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for domains file: %w", err)
	}

	absNormalResolver, err := filepath.Abs(normalResolver)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for normal resolver: %w", err)
	}

	absTrustedResolver, err := filepath.Abs(trustedResolver)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for trusted resolver: %w", err)
	}

	absOutputFile, err := filepath.Abs(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for output file: %w", err)
	}

	args := []string{
		"bruteforce",
		absWordlistFile,
		"--domains", absDomainsFile,
		"-r", absNormalResolver,
		"--resolvers-trusted", absTrustedResolver,
		"-w", absOutputFile,
		"-l", "100",
		"--rate-limit-trusted", "100",
		"--wildcard-tests", "30",
		"--wildcard-batch", "1000000",
	}

	if verbose {
		fmt.Printf("[DBG] executing: %s %s\n", purednsPath, strings.Join(args, " "))
	}

	cmd := exec.Command(purednsPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("puredns bruteforce failed: %w", err)
	}

	resolvedSubdomains, err := readResolvedSubdomains(absOutputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read puredns output: %w", err)
	}

	return resolvedSubdomains, nil
}
