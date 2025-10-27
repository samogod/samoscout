package active

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
)

type WordlistCleaner struct {
	regexes []*regexp.Regexp
}

func NewWordlistCleaner() *WordlistCleaner {
	patterns := []string{
		`[\!(,%]`,                              // ignore noisy characters
		`.{100,}`,                              // ignore lines with more than 100 characters (overly specific)
		`[0-9]{4,}`,                            // ignore lines with 4 or more consecutive digits (likely an id)
		`[0-9]{3,}$`,                           // ignore lines where the last 3 or more characters are digits (likely an id)
		`[a-z0-9]{32}`,                         // likely MD5 hash or similar
		`[0-9]+[A-Z0-9]{5,}`,                   // number followed by 5 or more numbers and uppercase letters (almost all noise)
		`\/.*\/.*\/.*\/.*\/.*\/.*\/`,           // ignore lines more than 6 directories deep (overly specific)
		`\w{8}-\w{4}-\w{4}-\w{4}-\w{12}`,       // ignore UUIDs
		`[0-9]+[a-zA-Z]+[0-9]+[a-zA-Z]+[0-9]+`, // ignore multiple numbers and letters mixed together (likely noise)
		`\.(png|jpg|jpeg|gif|svg|bmp|ttf|avif|wav|mp4|aac|ajax|css|all)$`, // ignore low value filetypes
		`^$`, // ignores blank lines
	}

	var regexes []*regexp.Regexp
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err == nil {
			regexes = append(regexes, re)
		}
	}

	return &WordlistCleaner{
		regexes: regexes,
	}
}

func (wc *WordlistCleaner) CleanWordlist(words []string) []string {
	var filtered []string
	for _, word := range words {
		if !wc.shouldFilter(word) {
			filtered = append(filtered, word)
		}
	}

	uniqueMap := make(map[string]bool)
	for _, word := range filtered {
		uniqueMap[word] = true
	}

	var result []string
	for word := range uniqueMap {
		result = append(result, word)
	}
	sort.Strings(result)

	return result
}

func (wc *WordlistCleaner) CleanWordlistFile(inputFile, outputFile string) (int, int, error) {
	words, err := readWordlistFile(inputFile)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read wordlist: %w", err)
	}

	originalSize := len(words)

	cleaned := wc.CleanWordlist(words)
	newSize := len(cleaned)

	if err := writeWordlistFile(cleaned, outputFile); err != nil {
		return 0, 0, fmt.Errorf("failed to write cleaned wordlist: %w", err)
	}

	return originalSize, newSize, nil
}

func (wc *WordlistCleaner) shouldFilter(line string) bool {
	for _, re := range wc.regexes {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

func readWordlistFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		words = append(words, line)
	}

	return words, scanner.Err()
}

func writeWordlistFile(words []string, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, word := range words {
		if _, err := writer.WriteString(word + "\n"); err != nil {
			return err
		}
	}

	return writer.Flush()
}

func CleanAndSaveWordlist(inputFile, outputFile string, verbose bool) error {
	cleaner := NewWordlistCleaner()

	if verbose {
		fmt.Printf("[DBG] cleaning wordlist: %s\n", inputFile)
	}

	originalSize, newSize, err := cleaner.CleanWordlistFile(inputFile, outputFile)
	if err != nil {
		return err
	}

	removed := originalSize - newSize

	if verbose {
		fmt.Printf("[DBG] removed %d lines, wordlist now has %d lines\n", removed, newSize)
	}

	return nil
}
