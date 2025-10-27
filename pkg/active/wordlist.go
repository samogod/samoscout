package active

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
)

func ExtractKeywords(subdomains []string, rootDomain string) ([]string, error) {
	wordCount := make(map[string]int)
	
	for _, subdomain := range subdomains {
		subdomain = strings.ToLower(strings.TrimSpace(subdomain))
		
		if strings.HasSuffix(subdomain, "."+rootDomain) {
			subdomain = strings.TrimSuffix(subdomain, "."+rootDomain)
		} else if subdomain == rootDomain {
			continue
		}
		
		parts := strings.Split(subdomain, ".")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			
			if part == "" || isNumericOnly(part) {
				continue
			}
			
			subParts := splitByDelimiters(part)
			for _, subPart := range subParts {
				if subPart != "" && !isNumericOnly(subPart) {
					wordCount[subPart]++
				}
			}
		}
	}
	
	type wordFreq struct {
		word  string
		count int
	}
	
	var words []wordFreq
	for word, count := range wordCount {
		words = append(words, wordFreq{word, count})
	}
	
	sort.Slice(words, func(i, j int) bool {
		if words[i].count == words[j].count {
			return words[i].word < words[j].word
		}
		return words[i].count > words[j].count
	})
	
	var result []string
	for _, w := range words {
		result = append(result, w.word)
	}
	
	return result, nil
}

func isNumericOnly(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

func splitByDelimiters(s string) []string {
	delimiters := []string{"-", "_", "~"}
	for _, delim := range delimiters {
		s = strings.ReplaceAll(s, delim, " ")
	}
	
	parts := strings.Fields(s)
	return parts
}

func WriteWordlist(keywords []string, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create wordlist file: %w", err)
	}
	defer file.Close()
	
	writer := bufio.NewWriter(file)
	for _, keyword := range keywords {
		if _, err := writer.WriteString(keyword + "\n"); err != nil {
			return fmt.Errorf("failed to write to wordlist: %w", err)
		}
	}
	
	return writer.Flush()
}

func ReadSubdomains(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
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
		return nil, fmt.Errorf("error reading file: %w", err)
	}
	
	return subdomains, nil
}

