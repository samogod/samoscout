package active

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type PipelineConfig struct {
	Domain             string
	PassiveSubdomains  []string
	OutputDir          string
	DsieveTop          int
	DsieveFactor       int
	Verbose            bool
	DeepEnum           bool
	CustomWordlistPath string
}

type PipelineResult struct {
	CustomWordlist     []string
	DsieveSubdomains   []string
	MksubSubdomains    []string
	ActiveSubdomains   []string
	TotalNewSubdomains int
	Duration           time.Duration
}

func RunActivePipeline(config PipelineConfig) (*PipelineResult, error) {
	startTime := time.Now()
	result := &PipelineResult{}

	if config.Verbose {
		fmt.Println("[DBG] starting active enumeration pipeline...")
	}

	domainDir := filepath.Join(config.OutputDir, config.Domain)
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	config.OutputDir = domainDir

	passiveFile := filepath.Join(config.OutputDir, "passive_subdomains.txt")
	if err := writeSubdomainsToFile(config.PassiveSubdomains, passiveFile); err != nil {
		return nil, fmt.Errorf("failed to save passive subdomains: %w", err)
	}
	if config.Verbose {
		fmt.Printf("[DBG] saved %d passive subdomains to %s\n", len(config.PassiveSubdomains), passiveFile)
	}

	if config.Verbose {
		fmt.Println("[DBG] extracting keywords from passive subdomains...")
	}
	keywords, err := ExtractKeywords(config.PassiveSubdomains, config.Domain)
	if err != nil {
		return nil, fmt.Errorf("failed to extract keywords: %w", err)
	}

	if config.Verbose {
		fmt.Println("[DBG] cleaning wordlist...")
	}
	cleaner := NewWordlistCleaner()
	cleanedKeywords := cleaner.CleanWordlist(keywords)
	result.CustomWordlist = cleanedKeywords

	wordlistFile := filepath.Join(config.OutputDir, "custom_wordlist.txt")
	if err := WriteWordlist(cleanedKeywords, wordlistFile); err != nil {
		return nil, fmt.Errorf("failed to write wordlist: %w", err)
	}
	if config.Verbose {
		removed := len(keywords) - len(cleanedKeywords)
		fmt.Printf("[DBG] custom wordlist: %d keywords (%d noise removed)\n", len(cleanedKeywords), removed)
	}

	if config.Verbose {
		fmt.Println("[DBG] running dsieve with factor=3...")
	}
	dsieveF3Output := filepath.Join(config.OutputDir, "dsieve_f3.txt")
	dsieveF3Subdomains, err := runDsieve(passiveFile, dsieveF3Output, config.DsieveTop, 3)
	if err != nil {
		return nil, fmt.Errorf("dsieve factor=3 failed: %w", err)
	}
	if config.Verbose {
		fmt.Printf("[DBG] dsieve factor=3: generated %d potential subdomains\n", len(dsieveF3Subdomains))
	}

	if config.Verbose {
		fmt.Println("[DBG] running dsieve with factor=4...")
	}
	dsieveF4Output := filepath.Join(config.OutputDir, "dsieve_f4.txt")
	dsieveF4Subdomains, err := runDsieve(passiveFile, dsieveF4Output, config.DsieveTop, config.DsieveFactor)
	if err != nil {
		return nil, fmt.Errorf("dsieve factor=4 failed: %w", err)
	}
	if config.Verbose {
		fmt.Printf("[DBG] dsieve factor=4: generated %d potential subdomains\n", len(dsieveF4Subdomains))
	}

	combinedDsieve := MergeAndDeduplicate(dsieveF3Subdomains, dsieveF4Subdomains)
	result.DsieveSubdomains = combinedDsieve

	var baseWordlistWords []string

	if config.CustomWordlistPath != "" {
		if config.Verbose {
			fmt.Printf("[DBG] using custom wordlist from: %s\n", config.CustomWordlistPath)
		}

		if _, err := os.Stat(config.CustomWordlistPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("custom wordlist file not found: %s", config.CustomWordlistPath)
		}

		baseWordlistWords, err = readDomainsList(config.CustomWordlistPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read custom wordlist: %w", err)
		}
		if config.Verbose {
			fmt.Printf("[DBG] custom wordlist: %d words loaded\n", len(baseWordlistWords))
		}
	} else {
		if config.Verbose {
			fmt.Println("[DBG] downloading six2dez default wordlist...")
		}
		six2dezFile := filepath.Join(config.OutputDir, "six2dez_wordlist.txt")
		if err := DownloadSix2dezWordlist(six2dezFile); err != nil {
			return nil, fmt.Errorf("failed to download six2dez wordlist: %w", err)
		}
		baseWordlistWords, err = readDomainsList(six2dezFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read six2dez wordlist: %w", err)
		}
		if config.Verbose {
			fmt.Printf("[DBG] six2dez wordlist: %d words loaded\n", len(baseWordlistWords))
		}
	}

	if config.Verbose {
		fmt.Println("[DBG] combining wordlists...")
	}
	combinedWords := CombineWordlists(cleanedKeywords, baseWordlistWords)
	combinedWordlistFile := filepath.Join(config.OutputDir, "combined_wordlist.txt")
	if err := WriteWordlist(combinedWords, combinedWordlistFile); err != nil {
		return nil, fmt.Errorf("failed to write combined wordlist: %w", err)
	}
	if config.Verbose {
		fmt.Printf("[DBG] combined wordlist: %d unique words\n", len(combinedWords))
	}

	if config.Verbose {
		fmt.Println("[DBG] running mksub for subdomain generation...")
		fmt.Printf("[DBG] note: using root domain only (%s) to avoid combinatorial explosion\n", config.Domain)
	}
	mksubOutput := filepath.Join(config.OutputDir, "mksub_output.txt")
	mksubSubdomains, err := runMksub(combinedWordlistFile, config.Domain, mksubOutput, config.Verbose)
	if err != nil {
		return nil, fmt.Errorf("mksub failed: %w", err)
	}
	result.MksubSubdomains = mksubSubdomains
	if config.Verbose {
		fmt.Printf("[DBG] mksub: generated %d potential subdomains\n", len(mksubSubdomains))
	}

	passiveSet := make(map[string]bool)
	for _, sub := range config.PassiveSubdomains {
		passiveSet[strings.ToLower(sub)] = true
	}

	newSubdomains := 0
	for _, sub := range append(combinedDsieve, mksubSubdomains...) {
		if !passiveSet[strings.ToLower(sub)] {
			newSubdomains++
		}
	}
	result.TotalNewSubdomains = newSubdomains

	allGeneratedSubdomains := MergeAndDeduplicate(
		config.PassiveSubdomains,
		combinedDsieve,
		mksubSubdomains,
	)

	totalGenerated := len(allGeneratedSubdomains)
	const maxSubdomains = 25000

	if totalGenerated > maxSubdomains {
		if config.Verbose {
			fmt.Printf("[DBG] shuffling %d subdomains and limiting to %d for resolution\n", totalGenerated, maxSubdomains)
		}

		rand.Seed(time.Now().UnixNano())
		rand.Shuffle(len(allGeneratedSubdomains), func(i, j int) {
			allGeneratedSubdomains[i], allGeneratedSubdomains[j] = allGeneratedSubdomains[j], allGeneratedSubdomains[i]
		})

		allGeneratedSubdomains = allGeneratedSubdomains[:maxSubdomains]
		fmt.Printf("[INF] Limited to %d subdomains (from %d total) for resolution\n", maxSubdomains, totalGenerated)
	} else {
		fmt.Printf("[INF] Total subdomains to resolve: %d\n", len(allGeneratedSubdomains))
	}

	resolvedSubdomains, err := ResolveDNS(allGeneratedSubdomains, config.OutputDir, config.Domain, config.Verbose)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed: %w", err)
	}

	fmt.Println("[ACTIVE] Running gotator permutations")

	if config.Verbose {
		fmt.Printf("[DBG] using %d active subdomains for permutation\n", len(resolvedSubdomains))
	}

	gotatorInputFile := filepath.Join(config.OutputDir, "resolved_subdomains.txt")

	gotatorOutputFile := filepath.Join(config.OutputDir, "gotator_output.txt")
	gotatorPerms, err := RunGotator(gotatorInputFile, "", gotatorOutputFile, 250, config.Verbose)
	if err != nil {
		return nil, fmt.Errorf("gotator failed: %w", err)
	}

	fmt.Printf("[ACTIVE] Generated %d permutations\n", len(gotatorPerms))

	if config.Verbose {
		fmt.Println("[DBG] resolving gotator permutations with puredns...")
	}

	gotatorResolvedFile := filepath.Join(config.OutputDir, "gotator_resolved.txt")
	normalResolverFile := filepath.Join(config.OutputDir, "resolvers.txt")
	trustedResolverFile := filepath.Join(config.OutputDir, "resolvers_trusted.txt")

	gotatorResolved, err := RunPureDnsWithTrusted(gotatorOutputFile, normalResolverFile, trustedResolverFile, gotatorResolvedFile, config.Domain, config.Verbose)
	if err != nil {
		return nil, fmt.Errorf("gotator permutation resolution failed: %w", err)
	}

	fmt.Printf("[ACTIVE] Resolved %d/%d permutations\n", len(gotatorResolved), len(gotatorPerms))

	finalActiveSubdomains := MergeAndDeduplicate(resolvedSubdomains, gotatorResolved)
	result.ActiveSubdomains = finalActiveSubdomains

	fmt.Printf("[ACTIVE] Enumeration complete: %d total active subdomains\n", len(finalActiveSubdomains))

	if config.DeepEnum {
		fmt.Println("[DEEP] Starting deep level enumeration...")

		deepSubdomains, err := RunDeepEnumeration(
			finalActiveSubdomains,
			config.OutputDir,
			config.Domain,
			config.Verbose,
		)
		if err != nil {
			return nil, fmt.Errorf("deep enumeration failed: %w", err)
		}

		fmt.Printf("[DEEP] Found %d additional subdomains\n", len(deepSubdomains))

		finalActiveSubdomains = MergeAndDeduplicate(finalActiveSubdomains, deepSubdomains)
		result.ActiveSubdomains = finalActiveSubdomains

		fmt.Printf("[DEEP] Total after deep enumeration: %d subdomains\n", len(finalActiveSubdomains))
	}

	newActiveSubdomains := 0
	for _, sub := range finalActiveSubdomains {
		if !passiveSet[strings.ToLower(sub)] {
			newActiveSubdomains++
		}
	}
	result.TotalNewSubdomains = newActiveSubdomains

	result.Duration = time.Since(startTime)
	return result, nil
}

func runDsieve(inputFile, outputFile string, top, factor int) ([]string, error) {
	levelFilter := fmt.Sprintf("%d", factor)

	results, err := RunDsieve(inputFile, outputFile, levelFilter, top)
	if err != nil {
		return nil, fmt.Errorf("dsieve failed: %w", err)
	}

	return results, nil
}

func runMksub(wordlistFile, domain, outputFile string, verbose bool) ([]string, error) {
	results, err := RunMksub(wordlistFile, domain, outputFile, verbose)
	if err != nil {
		return nil, fmt.Errorf("mksub failed: %w", err)
	}

	return results, nil
}

func writeSubdomainsToFile(subdomains []string, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, subdomain := range subdomains {
		if _, err := writer.WriteString(subdomain + "\n"); err != nil {
			return err
		}
	}

	return writer.Flush()
}

func readSubdomainsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var subdomains []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			subdomains = append(subdomains, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return subdomains, nil
}

func MergeAndDeduplicate(lists ...[]string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, list := range lists {
		for _, subdomain := range list {
			normalized := strings.ToLower(strings.TrimSpace(subdomain))
			if normalized != "" && !seen[normalized] {
				seen[normalized] = true
				result = append(result, subdomain)
			}
		}
	}

	return result
}
