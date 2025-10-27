package sources

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"samoscout/pkg/session"
	"strings"
)


type Dnsgrep struct{}


func (d *Dnsgrep) Name() string {
	return "dnsgrep"
}


func (d *Dnsgrep) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		url := fmt.Sprintf("https://www.dnsgrep.cn/subdomain/%s", domain)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Accept-Encoding", "gzip, deflate")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Upgrade-Insecure-Requests", "1")

		resp, err := s.Client.Do(req)
		if err != nil {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("failed to execute request: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
			return
		}

		body := make([]byte, 0, 32*1024)
		buf := make([]byte, 4096)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			n, err := resp.Body.Read(buf)
			if n > 0 {
				body = append(body, buf[:n]...)
			}
			if err != nil {
				break
			}
		}

		d.extractSubdomains(string(body), domain, results)
	}()

	return results
}


func (d *Dnsgrep) extractSubdomains(responseText, domain string, results chan<- Result) {
	seen := make(map[string]bool)

	subdomainPattern := regexp.MustCompile(`[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.` + regexp.QuoteMeta(domain) + `\b`)
	
	matches := subdomainPattern.FindAllString(responseText, -1)
	
	for _, match := range matches {
		subdomain := strings.TrimSpace(strings.ToLower(match))
		
		if subdomain != "" && subdomain != domain && !seen[subdomain] {
			seen[subdomain] = true
			
			select {
			case results <- Result{Source: d.Name(), Value: subdomain, Type: "subdomain"}:
			default:
			}
		}
	}
	
	jsonPattern := regexp.MustCompile(`["']([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.` + regexp.QuoteMeta(domain) + `)["']`)
	jsonMatches := jsonPattern.FindAllStringSubmatch(responseText, -1)
	
	for _, match := range jsonMatches {
		if len(match) >= 2 {
			subdomain := strings.TrimSpace(strings.ToLower(match[1]))
			
			if subdomain != "" && subdomain != domain && !seen[subdomain] {
				seen[subdomain] = true
				
				select {
				case results <- Result{Source: d.Name(), Value: subdomain, Type: "subdomain"}:
				default:
				}
			}
		}
	}
	
	htmlPattern := regexp.MustCompile(`(?:href|src)=["'](?:https?://)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.` + regexp.QuoteMeta(domain) + `)`)
	htmlMatches := htmlPattern.FindAllStringSubmatch(responseText, -1)
	
	for _, match := range htmlMatches {
		if len(match) >= 2 {
			subdomain := strings.TrimSpace(strings.ToLower(match[1]))
			
			if subdomain != "" && subdomain != domain && !seen[subdomain] {
				seen[subdomain] = true
				
				select {
				case results <- Result{Source: d.Name(), Value: subdomain, Type: "subdomain"}:
				default:
				}
			}
		}
	}
	
	lines := strings.Split(responseText, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		if strings.Contains(line, "."+domain) {
			lineSubdomains := subdomainPattern.FindAllString(line, -1)
			for _, match := range lineSubdomains {
				subdomain := strings.TrimSpace(strings.ToLower(match))
				
				if subdomain != "" && subdomain != domain && !seen[subdomain] {
					seen[subdomain] = true
					
					select {
					case results <- Result{Source: d.Name(), Value: subdomain, Type: "subdomain"}:
					default:
					}
				}
			}
		}
	}
}
