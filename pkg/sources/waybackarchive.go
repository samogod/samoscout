package sources

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"github.com/samogod/samoscout/pkg/session"
	"strings"
)


type WaybackArchive struct{}


func (w *WaybackArchive) Name() string {
	return "waybackarchive"
}


func (w *WaybackArchive) Run(ctx context.Context, domain string, session *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		seen := make(map[string]bool)
		apiURL := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=txt&fl=original&collapse=urlkey", domain)
		
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
		if err != nil {
			results <- Result{Source: w.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

		resp, err := session.Client.Do(req)
		if err != nil {
			results <- Result{Source: w.Name(), Error: fmt.Errorf("API request failed: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			results <- Result{Source: w.Name(), Error: fmt.Errorf("unexpected status code: %d", resp.StatusCode)}
			return
		}

		
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
			}

			line := scanner.Text()
			if line == "" {
				continue
			}

			
			if decodedLine, err := url.QueryUnescape(line); err == nil {
				line = decodedLine
			}
			
			
			subdomains := w.extractSubdomains(line, domain)
			
			for _, subdomain := range subdomains {
				
				subdomain = strings.ToLower(subdomain)
				subdomain = strings.TrimPrefix(subdomain, "25")
				subdomain = strings.TrimPrefix(subdomain, "2f")
				
				hostname := strings.TrimSpace(subdomain)
				
				if w.isValidHostname(hostname, domain) && !seen[hostname] {
					seen[hostname] = true

					select {
					case results <- Result{Source: w.Name(), Value: hostname, Type: "subdomain"}:
					case <-ctx.Done():
						return
					}
				}
			}
		}

		if err := scanner.Err(); err != nil {
			results <- Result{Source: w.Name(), Error: fmt.Errorf("scanner error: %w", err)}
		}
	}()

	return results
}


func (w *WaybackArchive) extractSubdomains(line, domain string) []string {
	var subdomains []string
	
	
	domainRegex := regexp.MustCompile(`([a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+)`)
	matches := domainRegex.FindAllStringSubmatch(line, -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			hostname := strings.TrimSpace(strings.ToLower(match[1]))
			
			
			if strings.HasSuffix(hostname, "."+domain) || hostname == domain {
				subdomains = append(subdomains, hostname)
			}
		}
	}
	
	return subdomains
}


func (w *WaybackArchive) isValidHostname(hostname, domain string) bool {
	if hostname == "" {
		return false
	}
	
	
	if strings.Contains(hostname, "..") || strings.HasPrefix(hostname, ".") || strings.HasSuffix(hostname, ".") {
		return false
	}
	
	
	if !strings.Contains(hostname, ".") {
		return false
	}
	
	
	if !strings.HasSuffix(hostname, "."+domain) && hostname != domain {
		return false
	}
	
	
	for _, char := range hostname {
		if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '.' || char == '-') {
			return false
		}
	}
	
	
	if len(hostname) > 253 {
		return false
	}
	
	return true
}
