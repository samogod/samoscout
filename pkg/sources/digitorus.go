package sources

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"samoscout/pkg/session"
	"strings"
)


type Digitorus struct{}


func (d *Digitorus) Name() string {
	return "digitorus"
}


func (d *Digitorus) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		url := fmt.Sprintf("https://certificatedetails.com/%s", domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

		resp, err := s.Client.Do(req)
		if err != nil {
			
			if resp != nil && resp.StatusCode == http.StatusNotFound {
				
			} else {
				results <- Result{Source: d.Name(), Error: fmt.Errorf("failed to execute request: %w", err)}
				return
			}
		}
		
		if resp == nil {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("no response received")}
			return
		}
		defer resp.Body.Close()

		
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
			return
		}

		
		scanner := bufio.NewScanner(resp.Body)
		seen := make(map[string]bool)
		
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}

			
			subdomains := d.extractSubdomains(line, domain)
			
			for _, subdomain := range subdomains {
				if subdomain != "" && !seen[subdomain] {
					seen[subdomain] = true
					
					select {
					case results <- Result{Source: d.Name(), Value: subdomain, Type: "subdomain"}:
					case <-ctx.Done():
						return
					}
				}
			}
		}

		
		if err := scanner.Err(); err != nil {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("scanner error: %w", err)}
		}
	}()

	return results
}


func (d *Digitorus) extractSubdomains(line, domain string) []string {
	var subdomains []string
	
	
	words := strings.Fields(line)
	for _, word := range words {
		
		if strings.Contains(word, domain) {
			
			candidates := d.splitBySeparators(word)
			
			for _, candidate := range candidates {
				hostname := d.cleanHostname(candidate, domain)
				if hostname != "" {
					subdomains = append(subdomains, hostname)
				}
			}
		}
	}
	
	return subdomains
}


func (d *Digitorus) splitBySeparators(text string) []string {
	var results []string
	
	
	separators := []string{" ", "\t", ",", ";", "(", ")", "[", "]", "{", "}", "\"", "'", "<", ">", "|"}
	
	current := []string{text}
	for _, sep := range separators {
		var next []string
		for _, part := range current {
			split := strings.Split(part, sep)
			next = append(next, split...)
		}
		current = next
	}
	
	
	for _, part := range current {
		if strings.TrimSpace(part) != "" {
			results = append(results, strings.TrimSpace(part))
		}
	}
	
	return results
}


func (d *Digitorus) cleanHostname(raw, domain string) string {
	hostname := strings.ToLower(strings.TrimSpace(raw))
	
	
	hostname = strings.TrimPrefix(hostname, ".")
	
	
	hostname = strings.Trim(hostname, ".,;:!?()[]{}\"'/\\*")
	
	
	if strings.Contains(hostname, "://") {
		parts := strings.Split(hostname, "://")
		if len(parts) > 1 {
			hostname = parts[1]
		}
	}
	
	
	if slashIndex := strings.Index(hostname, "/"); slashIndex > 0 {
		hostname = hostname[:slashIndex]
	}
	if questionIndex := strings.Index(hostname, "?"); questionIndex > 0 {
		hostname = hostname[:questionIndex]
	}
	
	
	if colonIndex := strings.LastIndex(hostname, ":"); colonIndex > 0 {
		if portPart := hostname[colonIndex+1:]; d.isNumeric(portPart) {
			hostname = hostname[:colonIndex]
		}
	}
	
	
	if hostname != "" && hostname != domain && 
	   strings.HasSuffix(hostname, "."+domain) && 
	   d.isValidHostname(hostname) {
		return hostname
	}
	
	return ""
}


func (d *Digitorus) isNumeric(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}


func (d *Digitorus) isValidHostname(hostname string) bool {
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
