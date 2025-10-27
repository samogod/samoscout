package sources

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"samoscout/pkg/session"
	"strconv"
	"strings"
)


type RapidDNS struct{}


var pagePattern = regexp.MustCompile(`class="page-link" href="/subdomain/[^"]+\?page=(\d+)">`)


func (r *RapidDNS) Name() string {
	return "rapiddns"
}


func (r *RapidDNS) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		page := 1
		maxPages := 1
		seen := make(map[string]bool)

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			
			url := fmt.Sprintf("https://rapiddns.io/subdomain/%s?page=%d&full=1", domain, page)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				results <- Result{Source: r.Name(), Error: fmt.Errorf("failed to create request for page %d: %w", page, err)}
				return
			}

			
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")

			resp, err := s.Client.Do(req)
			if err != nil {
				results <- Result{Source: r.Name(), Error: fmt.Errorf("failed to execute request for page %d: %w", page, err)}
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				results <- Result{Source: r.Name(), Error: fmt.Errorf("HTTP error for page %d: %d", page, resp.StatusCode)}
				return
			}

			
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				results <- Result{Source: r.Name(), Error: fmt.Errorf("failed to read response body for page %d: %w", page, err)}
				return
			}

			src := string(body)

			
			subdomains := r.extractSubdomains(src, domain)
			for _, subdomain := range subdomains {
				if !seen[subdomain] {
					seen[subdomain] = true

					select {
					case results <- Result{Source: r.Name(), Value: subdomain, Type: "subdomain"}:
					case <-ctx.Done():
						return
					}
				}
			}

			
			if maxPages == 1 {
				matches := pagePattern.FindAllStringSubmatch(src, -1)
				if len(matches) > 0 {
					lastMatch := matches[len(matches)-1]
					if len(lastMatch) > 1 {
						if maxPagesFound, err := strconv.Atoi(lastMatch[1]); err == nil {
							maxPages = maxPagesFound
						}
					}
				}
			}

			
			if page >= maxPages {
				break
			}
			page++
		}
	}()

	return results
}


func (r *RapidDNS) extractSubdomains(html, domain string) []string {
	var subdomains []string
	
	
	
	
	
	domainPattern := regexp.MustCompile(`(?i)([a-z0-9]([a-z0-9\-]*[a-z0-9])?\.)+` + regexp.QuoteMeta(domain))
	
	matches := domainPattern.FindAllString(html, -1)
	for _, match := range matches {
		hostname := strings.TrimSpace(strings.ToLower(match))
		
		
		if hostname != "" && hostname != domain && 
		   strings.HasSuffix(hostname, "."+domain) && 
		   r.isValidHostname(hostname) {
			subdomains = append(subdomains, hostname)
		}
	}
	
	return subdomains
}


func (r *RapidDNS) isValidHostname(hostname string) bool {
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

	
	for _, char := range hostname {
		if !((char >= 'a' && char <= 'z') || 
			 (char >= '0' && char <= '9') || 
			 char == '-' || char == '.') {
			return false
		}
	}

	
	if strings.HasPrefix(hostname, "-") || strings.HasSuffix(hostname, "-") {
		return false
	}

	if strings.Contains(hostname, "--") {
		return false
	}

	return true
}
