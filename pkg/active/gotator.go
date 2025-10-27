package active

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Gotator - Subdomain permutation tool
// Direct implementation from https://github.com/Josue87/gotator (MIT License)

var (
	gotatorAllDomains         []string
	gotatorPermutations       []string
	gotatorMinimizeDuplicates bool
)

var DefaultPermutations = []string{
	"prod", "dev", "stage", "infra", "cfg", "ops", "production", "staging", "static", "admin",
}

func RunGotator(subdomainFile, permFile, outputFile string, threads int, verbose bool) ([]string, error) {
	subdomains, err := readGotatorSubdomains(subdomainFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read subdomains: %w", err)
	}

	if len(subdomains) == 0 {
		return nil, fmt.Errorf("no valid subdomains found")
	}

	gotatorAllDomains = subdomains
	gotatorPermutations = DefaultPermutations
	gotatorMinimizeDuplicates = true

	if verbose {
		fmt.Printf("[DBG] loaded %d subdomains and %d permutation words\n", len(subdomains), len(gotatorPermutations))
	}

	var results []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	guardThreads := make(chan struct{}, threads)

	for _, domain := range subdomains {
		guardThreads <- struct{}{}
		wg.Add(1)
		go func(d string) {
			defer func() {
				<-guardThreads
				wg.Done()
			}()
			
			perms := gotatorWorker(d, 1)
			
			mu.Lock()
			results = append(results, perms...)
			mu.Unlock()
		}(domain)
	}

	wg.Wait()

	if verbose {
		fmt.Printf("[DBG] generated %d permutations\n", len(results))
	}

	if outputFile != "" {
		if err := writeGotatorOutput(results, outputFile); err != nil {
			return nil, fmt.Errorf("failed to write output: %w", err)
		}
	}

	return results, nil
}

func gotatorWorker(domain string, depth uint) []string {
	var results []string
	results = append(results, domain)
	perms := gotatorPermutator(domain, depth, true)
	results = append(results, perms...)
	return results
}

func gotatorPermutator(domain string, depth uint, firstTime bool) []string {
	var results []string
	
	if depth < 1 {
		return results
	}

	for _, perm := range gotatorPermutations {
		if perm == "" {
			continue
		}
		
		joins := gotatorGetJoins(domain, perm, firstTime)
		
		for _, j := range joins {
			newSubDomain := perm + j + domain
			if !gotatorContains(gotatorAllDomains, newSubDomain) && !gotatorContains(results, newSubDomain) {
				results = append(results, newSubDomain)
				if depth > 1 {
					subPerms := gotatorPermutator(newSubDomain, depth-1, false)
					results = append(results, subPerms...)
				}
			}
		}
	}
	
	return results
}

func gotatorGetJoins(domain string, perm string, firstTime bool) []string {
	joins := []string{".", "-", ""}
	allNumbers := []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}
	
	numberPrefix := false
	if gotatorMinimizeDuplicates {
		for _, n := range allNumbers {
			if strings.HasPrefix(domain, n) {
				numberPrefix = true
				break
			}
		}
	}

	if numberPrefix {
		for _, n := range allNumbers {
			if strings.HasSuffix(perm, n) {
				joins = []string{}
				break
			}
		}
	} else if gotatorMinimizeDuplicates {
		firstElement := strings.Split(domain, ".")[0]
		if firstElement == perm {
			joins = []string{}
		} else if len(perm) >= 4 && strings.HasPrefix(firstElement, perm) {
			joins = []string{".", "-"}
		} else {
			subdomainFirstElement := gotatorRemoveNumbers(firstElement)
			newPermutation := gotatorRemoveNumbers(perm)
			if subdomainFirstElement == newPermutation {
				joins = []string{}
			} else if strings.HasSuffix(subdomainFirstElement, newPermutation) {
				joins = []string{"."}
			}
		}
	}
	
	return joins
}

func gotatorRemoveNumbers(element string) string {
	pattern := regexp.MustCompile("\\d+")
	aux := element
	for _, data := range pattern.FindStringSubmatch(element) {
		aux = strings.Replace(aux, data, "", -1)
	}
	return aux
}

func gotatorContains(slice []string, str string) bool {
	for _, v := range slice {
		if v == str {
			return true
		}
	}
	return false
}

func readGotatorSubdomains(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var subdomains []string
	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") && len(strings.Split(line, ".")) >= 2 {
			subdomains = append(subdomains, line)
		}
	}

	return subdomains, scanner.Err()
}

func writeGotatorOutput(perms []string, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, perm := range perms {
		if _, err := writer.WriteString(perm + "\n"); err != nil {
			return err
		}
	}

	return writer.Flush()
}

func gotatorPermutatorNumbers(permutations *[]string, permutation string, dataToReplace [][]string, permutatorNumber uint) {
	defer func() {
		recover()
	}()
	for _, numberToReplace := range dataToReplace {
		intNumber, err := strconv.Atoi(numberToReplace[0])
		if err != nil {
			continue
		}
		for i := 1; i <= int(permutatorNumber); i++ {
			*permutations = append(*permutations, strings.Replace(permutation, numberToReplace[0], strconv.Itoa(intNumber+i), -1))
			if (intNumber - i) >= 0 {
				*permutations = append(*permutations, strings.Replace(permutation, numberToReplace[0], strconv.Itoa(intNumber-i), -1))
			}
		}
	}
}

