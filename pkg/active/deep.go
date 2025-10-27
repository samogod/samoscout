package active

import (
	"fmt"
	"path/filepath"
	"sync"
)

func RunDeepEnumeration(resolvedSubdomains []string, outputDir, domain string, verbose bool) ([]string, error) {
	if verbose {
		fmt.Println("[DBG] starting deep level enumeration...")
	}

	finalSubsFile := filepath.Join(outputDir, "final_subdomains.txt")
	if err := writeSubdomainsToFile(resolvedSubdomains, finalSubsFile); err != nil {
		return nil, fmt.Errorf("failed to write final subdomains: %w", err)
	}

	if verbose {
		fmt.Printf("[DBG] running parallel dsieve (f3, f4, f5) on %d subdomains...\n", len(resolvedSubdomains))
	}

	type dsieveResult struct {
		factor     string
		subdomains []string
		err        error
	}

	results := make(chan dsieveResult, 3)
	var wg sync.WaitGroup

	factors := []struct {
		factor string
		level  string
	}{
		{"3", "3"},
		{"4", "4"},
		{"5", "5"},
	}

	for _, f := range factors {
		wg.Add(1)
		go func(factor, level string) {
			defer wg.Done()

			outputFile := filepath.Join(outputDir, fmt.Sprintf("dsieve_f%s_output.txt", factor))
			subs, err := RunDsieve(finalSubsFile, outputFile, level, 5)

			results <- dsieveResult{
				factor:     factor,
				subdomains: subs,
				err:        err,
			}

			if verbose && err == nil {
				fmt.Printf("[DBG] dsieve f%s: generated %d subdomains\n", factor, len(subs))
			}
		}(f.factor, f.level)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var f3, f4, f5 []string
	for result := range results {
		if result.err != nil {
			return nil, fmt.Errorf("dsieve f%s failed: %w", result.factor, result.err)
		}

		switch result.factor {
		case "3":
			f3 = result.subdomains
		case "4":
			f4 = result.subdomains
		case "5":
			f5 = result.subdomains
		}
	}

	fmt.Printf("[DEEP] Dsieve generated: f3=%d, f4=%d, f5=%d subdomains\n", len(f3), len(f4), len(f5))

	if verbose {
		fmt.Println("[DBG] downloading and merging Trickest wordlists...")
	}

	level2, level3, level4plus, err := DownloadAndMergeTrickestWordlists(outputDir, verbose)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare wordlists: %w", err)
	}

	normalResolverFile := filepath.Join(outputDir, "resolvers.txt")
	trustedResolverFile := filepath.Join(outputDir, "resolvers_trusted.txt")

	if verbose {
		fmt.Println("[DBG] running puredns bruteforce (3 levels)...")
	}

	fmt.Println("[DEEP] Starting bruteforce with level2 wordlist...")
	resolvedF3, err := RunPurednsBruteforce(level2, f3, normalResolverFile, trustedResolverFile, outputDir, domain, verbose)
	if err != nil {
		return nil, fmt.Errorf("bruteforce f3 failed: %w", err)
	}
	fmt.Printf("[DEEP] Level2 bruteforce: %d/%d resolved\n", len(resolvedF3), len(f3))

	outputF3File := filepath.Join(outputDir, "deep_f3_resolved.txt")
	if err := writeSubdomainsToFile(resolvedF3, outputF3File); err != nil {
		return nil, fmt.Errorf("failed to write f3 results: %w", err)
	}

	fmt.Println("[DEEP] Starting bruteforce with level3 wordlist...")
	resolvedF4, err := RunPurednsBruteforce(level3, f4, normalResolverFile, trustedResolverFile, outputDir, domain, verbose)
	if err != nil {
		return nil, fmt.Errorf("bruteforce f4 failed: %w", err)
	}
	fmt.Printf("[DEEP] Level3 bruteforce: %d/%d resolved\n", len(resolvedF4), len(f4))

	outputF4File := filepath.Join(outputDir, "deep_f4_resolved.txt")
	if err := writeSubdomainsToFile(resolvedF4, outputF4File); err != nil {
		return nil, fmt.Errorf("failed to write f4 results: %w", err)
	}

	fmt.Println("[DEEP] Starting bruteforce with level4plus wordlist...")
	resolvedF5, err := RunPurednsBruteforce(level4plus, f5, normalResolverFile, trustedResolverFile, outputDir, domain, verbose)
	if err != nil {
		return nil, fmt.Errorf("bruteforce f5 failed: %w", err)
	}
	fmt.Printf("[DEEP] Level4plus bruteforce: %d/%d resolved\n", len(resolvedF5), len(f5))

	outputF5File := filepath.Join(outputDir, "deep_f5_resolved.txt")
	if err := writeSubdomainsToFile(resolvedF5, outputF5File); err != nil {
		return nil, fmt.Errorf("failed to write f5 results: %w", err)
	}

	allDeepSubdomains := MergeAndDeduplicate(resolvedF3, resolvedF4, resolvedF5)

	if verbose {
		fmt.Printf("[DBG] deep enumeration complete: %d total unique subdomains\n", len(allDeepSubdomains))
	}

	return allDeepSubdomains, nil
}
