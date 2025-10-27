package sources

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"samoscout/pkg/session"
	"strings"
)


type Robtex struct{}


type RobtexResult struct {
	Rrname string `json:"rrname"`
	Rrdata string `json:"rrdata"`
	Rrtype string `json:"rrtype"`
}

const (
	addrRecord     = "A"
	iPv6AddrRecord = "AAAA"
	robtexBaseURL  = "https://proapi.robtex.com/pdns"
)


func (r *Robtex) Name() string {
	return "robtex"
}


func (r *Robtex) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		if s.Keys.Robtex == "" {
			results <- Result{Source: r.Name(), Error: fmt.Errorf("Robtex API key not configured")}
			return
		}

		seen := make(map[string]bool)

		
		forwardURL := fmt.Sprintf("%s/forward/%s?key=%s", robtexBaseURL, domain, s.Keys.Robtex)
		ips, err := r.enumerate(ctx, forwardURL, s)
		if err != nil {
			results <- Result{Source: r.Name(), Error: fmt.Errorf("forward lookup failed: %w", err)}
			return
		}

		
		for _, result := range ips {
			if result.Rrtype == addrRecord || result.Rrtype == iPv6AddrRecord {
				select {
				case <-ctx.Done():
					return
				default:
				}

				
				reverseURL := fmt.Sprintf("%s/reverse/%s?key=%s", robtexBaseURL, result.Rrdata, s.Keys.Robtex)
				domains, err := r.enumerate(ctx, reverseURL, s)
				if err != nil {
					results <- Result{Source: r.Name(), Error: fmt.Errorf("reverse lookup failed for %s: %w", result.Rrdata, err)}
					continue
				}

				
				for _, domainResult := range domains {
					hostname := strings.TrimSpace(strings.ToLower(domainResult.Rrdata))
					
					
					if hostname != "" && hostname != domain && 
					   strings.HasSuffix(hostname, "."+domain) && 
					   r.isValidHostname(hostname) && !seen[hostname] {
						seen[hostname] = true

						select {
						case results <- Result{Source: r.Name(), Value: hostname, Type: "subdomain"}:
						case <-ctx.Done():
							return
						}
					}
				}
			}
		}
	}()

	return results
}


func (r *Robtex) enumerate(ctx context.Context, targetURL string, s *session.Session) ([]RobtexResult, error) {
	var results []RobtexResult

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return results, fmt.Errorf("failed to create request: %w", err)
	}

	
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "application/x-ndjson")
	req.Header.Set("Content-Type", "application/x-ndjson")

	resp, err := s.Client.Do(req)
	if err != nil {
		return results, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return results, fmt.Errorf("invalid Robtex API key")
	}

	if resp.StatusCode == 429 {
		return results, fmt.Errorf("Robtex rate limit exceeded")
	}

	if resp.StatusCode != http.StatusOK {
		return results, fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var response RobtexResult
		if err := json.NewDecoder(bytes.NewBufferString(line)).Decode(&response); err != nil {
			continue 
		}

		results = append(results, response)
	}

	if err := scanner.Err(); err != nil {
		return results, fmt.Errorf("error reading response: %w", err)
	}

	return results, nil
}


func (r *Robtex) isValidHostname(hostname string) bool {
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
