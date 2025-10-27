package active

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
)

// Mksub - Generate subdomain combinations
// Direct copy from https://github.com/trickest/mksub (MIT License)

func RunMksub(wordlistFile, domain, outputFile string, verbose bool) ([]string, error) {
	words, err := readWordlist(wordlistFile, "")
	if err != nil {
		return nil, fmt.Errorf("failed to read wordlist: %w", err)
	}
	
	if verbose {
		fmt.Printf("[DBG] loaded %d unique words from wordlist\n", len(words))
	}
	
	domains := []string{domain}
	
	if verbose {
		fmt.Printf("[DBG] target domain: %s\n", domain)
		fmt.Printf("[DBG] generating combinations: %d words × 1 domain = ~%d subdomains\n", 
			len(words), len(words))
	}
	
	subdomains := generateSubdomains(words, domains, 1, 100, verbose)
	
	if verbose {
		fmt.Printf("[DBG] generated %d unique subdomains\n", len(subdomains))
	}
	
	if outputFile != "" {
		if err := writeSubdomainsList(subdomains, outputFile); err != nil {
			return nil, err
		}
	}
	
	return subdomains, nil
}

func readWordlist(filePath, regexPattern string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	var re *regexp.Regexp
	if regexPattern != "" {
		re, err = regexp.Compile(regexPattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex: %w", err)
		}
	}
	
	uniqueWords := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word == "" {
			continue
		}
		
		wordLower := strings.ToLower(word)
		
		if re != nil && !re.MatchString(word) {
			continue
		}
		
		uniqueWords[wordLower] = true
	}
	
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	
	var words []string
	for word := range uniqueWords {
		words = append(words, word)
	}
	
	return words, nil
}

func generateSubdomains(words []string, domains []string, level int, threads int, verbose bool) []string {
	var mu sync.Mutex
	results := make(map[string]bool)
	totalProcessed := 0
	
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		
		currentLevel := []string{domain}
		
		for l := 1; l <= level; l++ {
			nextLevel := make(map[string]bool)
			var wg sync.WaitGroup
			semaphore := make(chan struct{}, threads)
			
			for _, baseDomain := range currentLevel {
				for _, word := range words {
					wg.Add(1)
					semaphore <- struct{}{}
					
					go func(base, w string) {
						defer wg.Done()
						defer func() { <-semaphore }()
						
						subdomain := fmt.Sprintf("%s.%s", w, base)
						
						mu.Lock()
						results[subdomain] = true
					nextLevel[subdomain] = true
					totalProcessed++
					
					if verbose && totalProcessed%10000 == 0 {
						fmt.Printf("[DBG] progress: %d subdomains generated...\r", totalProcessed)
					}
					mu.Unlock()
					}(baseDomain, word)
				}
			}
			
			wg.Wait()
			
			if verbose {
				fmt.Printf("\n")
			}
			
			currentLevel = make([]string, 0, len(nextLevel))
			for sub := range nextLevel {
				currentLevel = append(currentLevel, sub)
			}
		}
	}
	
	var subdomains []string
	for sub := range results {
		subdomains = append(subdomains, sub)
	}
	
	return subdomains
}

func readDomainsList(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	var domains []string
	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			domains = append(domains, line)
		}
	}
	
	return domains, scanner.Err()
}

func writeSubdomainsList(subdomains []string, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	
	writer := bufio.NewWriter(file)
	for _, sub := range subdomains {
		if _, err := writer.WriteString(sub + "\n"); err != nil {
			return err
		}
	}
	
	return writer.Flush()
}

