package sources

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"github.com/samogod/samoscout/pkg/session"
	"strings"
)


type DigiCert struct{}


func (d *DigiCert) Name() string {
	return "digicert"
}


func (d *DigiCert) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		url := fmt.Sprintf("https://ssltools.digicert.com/chainTester/webservice/ctsearch/search?keyword=%s", domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")

		resp, err := s.Client.Do(req)
		if err != nil {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("API request failed: %w", err)}
			return
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			results <- Result{Source: d.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
			return
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("failed to read response body: %w", err)}
			return
		}

		src := string(body)

		
		seen := make(map[string]bool)
		subdomains := d.extractSubdomains(src, domain, seen)
		
		for _, subdomain := range subdomains {
			select {
			case results <- Result{Source: d.Name(), Value: subdomain, Type: "subdomain"}:
			case <-ctx.Done():
				return
			}
		}
	}()

	return results
}


func (d *DigiCert) extractSubdomains(content, domain string, seen map[string]bool) []string {
	var subdomains []string
	
	
	
	domainRegex := regexp.MustCompile(`([a-zA-Z0-9.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := domainRegex.FindAllStringSubmatch(content, -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			hostname := strings.TrimSpace(strings.ToLower(match[1]))
			
			
			if d.isValidHostname(hostname) && !seen[hostname] {
				seen[hostname] = true
				subdomains = append(subdomains, hostname)
			}
		}
	}
	
	
	if len(subdomains) == 0 {
		generalRegex := regexp.MustCompile(`([a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+)`)
		generalMatches := generalRegex.FindAllStringSubmatch(content, -1)
		
		for _, match := range generalMatches {
			if len(match) > 1 {
				hostname := strings.TrimSpace(strings.ToLower(match[1]))
				
				
				if strings.Contains(hostname, domain) && d.isValidHostname(hostname) && !seen[hostname] {
					seen[hostname] = true
					subdomains = append(subdomains, hostname)
				}
			}
		}
	}
	
	return subdomains
}


func (d *DigiCert) isValidHostname(hostname string) bool {
	if hostname == "" {
		return false
	}
	
	
	if len(hostname) < 3 {
		return false
	}
	
	
	if strings.Contains(hostname, " ") || strings.Contains(hostname, "\t") || strings.Contains(hostname, "\n") {
		return false
	}
	
	
	if strings.HasPrefix(hostname, ".") || strings.HasSuffix(hostname, ".") {
		return false
	}
	
	
	if !strings.Contains(hostname, ".") {
		return false
	}
	
	
	if strings.Contains(hostname, "..") {
		return false
	}
	
	
	if strings.Contains(hostname, "*") {
		return false
	}
	
	return true
}
