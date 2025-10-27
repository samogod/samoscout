package sources

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"samoscout/pkg/session"
	"strings"
)


type HackerTarget struct{}


func (h *HackerTarget) Name() string {
	return "hackertarget"
}


func (h *HackerTarget) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- Result{Source: h.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		req.Header.Set("Accept", "text/plain")

		resp, err := s.Client.Do(req)
		if err != nil {
			results <- Result{Source: h.Name(), Error: fmt.Errorf("failed to execute request: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == 429 {
			results <- Result{Source: h.Name(), Error: fmt.Errorf("HackerTarget rate limit exceeded")}
			return
		}

		if resp.StatusCode != http.StatusOK {
			results <- Result{Source: h.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
			return
		}

		
		scanner := bufio.NewScanner(resp.Body)
		seen := make(map[string]bool)
		
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}

			
			
			subdomains := h.extractSubdomains(line, domain)
			
			for _, subdomain := range subdomains {
				if subdomain != "" && !seen[subdomain] {
					seen[subdomain] = true
					
					select {
					case results <- Result{Source: h.Name(), Value: subdomain, Type: "subdomain"}:
					case <-ctx.Done():
						return
					}
				}
			}
		}

		
		if err := scanner.Err(); err != nil {
			results <- Result{Source: h.Name(), Error: fmt.Errorf("scanner error: %w", err)}
		}
	}()

	return results
}


func (h *HackerTarget) extractSubdomains(line, domain string) []string {
	var subdomains []string
	
	
	
	parts := strings.Split(line, ",")
	if len(parts) > 0 {
		hostname := strings.TrimSpace(strings.ToLower(parts[0]))
		
		
		if hostname != "" && hostname != domain && 
		   strings.HasSuffix(hostname, "."+domain) && 
		   h.isValidHostname(hostname) {
			subdomains = append(subdomains, hostname)
		}
	}
	
	
	words := strings.Fields(line)
	for _, word := range words {
		
		if strings.Contains(word, ".") {
			
			cleanWord := strings.Trim(word, ".,;:!?()[]{}\"'/\\")
			cleanWord = strings.ToLower(cleanWord)
			
			
			if cleanWord != "" && cleanWord != domain && 
			   strings.HasSuffix(cleanWord, "."+domain) && 
			   h.isValidHostname(cleanWord) {
				subdomains = append(subdomains, cleanWord)
			}
		}
	}
	
	return subdomains
}


func (h *HackerTarget) isValidHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}

	
	if strings.HasPrefix(hostname, ".") || strings.HasSuffix(hostname, ".") {
		return false
	}

	if strings.Contains(hostname, "..") {
		return false
	}

	
	if !strings.Contains(hostname, ".") {
		return false
	}

	return true
}
