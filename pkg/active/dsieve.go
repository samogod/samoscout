package active

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Dsieve filters and enriches subdomains by level
// Based on https://github.com/trickest/dsieve (MIT License)

type DsieveConfig struct {
	InputFile  string
	OutputFile string
	Level      string
	Top        int
}

type domainCount struct {
	domain string
	count  int
}

func RunDsieve(inputFile, outputFile string, level string, top int) ([]string, error) {
	domains, err := readDomains(inputFile)
	if err != nil {
		return nil, err
	}

	minLevel, maxLevel, err := parseLevel(level)
	if err != nil {
		return nil, err
	}

	var results []string
	domainMap := make(map[string]bool)
	subdomainCounts := make(map[string]int)
	targetLevel := 0

	for _, domain := range domains {
		parts := extractDomainParts(domain)
		if len(parts) == 0 {
			continue
		}

		if targetLevel == 0 && minLevel > 0 {
			targetLevel = minLevel
		}

		if top > 0 {
			for i := range parts {
				d := strings.Join(parts[i:], ".")
				subdomainCounts[d]++
			}
		}

		for i := range parts {
			level := len(parts) - i
			if (minLevel == -1 || level >= minLevel) && (maxLevel == -1 || level <= maxLevel) {
				d := strings.Join(parts[i:], ".")
				if !domainMap[d] {
					domainMap[d] = true
					results = append(results, d)
				}
			}
		}
	}

	if top > 0 && len(subdomainCounts) > 0 {
		results = applyTopFilter(results, subdomainCounts, top, targetLevel)
	}

	if outputFile != "" {
		if err := writeDomains(results, outputFile); err != nil {
			return nil, err
		}
	}

	return results, nil
}

func extractDomainParts(input string) []string {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil
	}

	if strings.Contains(input, "://") {
		u, err := url.Parse(input)
		if err == nil && u.Host != "" {
			input = u.Host
		}
	}

	if idx := strings.Index(input, ":"); idx > 0 {
		input = input[:idx]
	}

	parts := strings.Split(input, ".")

	var filtered []string
	for _, part := range parts {
		if part != "" {
			filtered = append(filtered, part)
		}
	}

	return filtered
}

func parseLevel(level string) (int, int, error) {
	if level == "" {
		return -1, -1, nil
	}

	if !strings.Contains(level, ":") {
		l, err := strconv.Atoi(level)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid level format: %s", level)
		}
		return l, l, nil
	}

	parts := strings.Split(level, ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid level range: %s", level)
	}

	var minLevel, maxLevel int = -1, -1

	if parts[0] != "" {
		var err error
		minLevel, err = strconv.Atoi(parts[0])
		if err != nil {
			return 0, 0, fmt.Errorf("invalid min level: %s", parts[0])
		}
	}

	if parts[1] != "" {
		var err error
		maxLevel, err = strconv.Atoi(parts[1])
		if err != nil {
			return 0, 0, fmt.Errorf("invalid max level: %s", parts[1])
		}
	}

	return minLevel, maxLevel, nil
}

func applyTopFilter(domains []string, counts map[string]int, top int, targetLevel int) []string {
	var sorted []domainCount
	for d, c := range counts {
		parts := strings.Split(d, ".")
		if len(parts) == targetLevel {
			sorted = append(sorted, domainCount{d, c})
		}
	}

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})

	if top < len(sorted) {
		sorted = sorted[:top]
	}

	topMap := make(map[string]bool)
	for _, dc := range sorted {
		topMap[dc.domain] = true
	}

	var filtered []string
	for _, d := range domains {
		for topDomain := range topMap {
			if d == topDomain || strings.HasSuffix(d, "."+topDomain) {
				filtered = append(filtered, d)
				break
			}
		}
	}

	return filtered
}

func readDomains(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			domains = append(domains, line)
		}
	}

	return domains, scanner.Err()
}

func writeDomains(domains []string, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, domain := range domains {
		if _, err := writer.WriteString(domain + "\n"); err != nil {
			return err
		}
	}

	return writer.Flush()
}
