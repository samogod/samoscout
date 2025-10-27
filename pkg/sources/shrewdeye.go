package sources

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"samoscout/pkg/session"
	"strings"
)

type ShrewdEye struct{}

func (s *ShrewdEye) Name() string {
	return "shrewdeye"
}

func (s *ShrewdEye) Run(ctx context.Context, domain string, sess *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		url := fmt.Sprintf("https://shrewdeye.app/domains/%s.txt", domain)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- Result{Source: s.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		req.Header.Set("Accept", "text/plain")

		resp, err := sess.Client.Do(req)
		if err != nil {
			results <- Result{Source: s.Name(), Error: fmt.Errorf("failed to execute request: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == 404 {
			return
		}

		if resp.StatusCode == 429 {
			results <- Result{Source: s.Name(), Error: fmt.Errorf("ShrewdEye rate limit exceeded")}
			return
		}

		if resp.StatusCode != http.StatusOK {
			results <- Result{Source: s.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
			return
		}

		scanner := bufio.NewScanner(resp.Body)
		seen := make(map[string]bool)
		
		for scanner.Scan() {
			line := scanner.Text()
			
			if line == "" {
				continue
			}

			subdomain := strings.TrimSpace(strings.ToLower(line))
			
			if s.isValidSubdomain(subdomain, domain) && !seen[subdomain] {
				seen[subdomain] = true
				
				select {
				case results <- Result{Source: s.Name(), Value: subdomain, Type: "subdomain"}:
				case <-ctx.Done():
					return
				}
			}
		}

		if err := scanner.Err(); err != nil {
			results <- Result{Source: s.Name(), Error: fmt.Errorf("scanner error: %w", err)}
			return
		}
	}()

	return results
}

func (s *ShrewdEye) isValidSubdomain(subdomain, domain string) bool {
	if subdomain == "" || subdomain == domain {
		return false
	}

	if !strings.HasSuffix(subdomain, "."+domain) && subdomain != domain {
		return false
	}

	if len(subdomain) == 0 || len(subdomain) > 253 {
		return false
	}

	if strings.HasPrefix(subdomain, ".") || strings.HasSuffix(subdomain, ".") {
		return false
	}

	if strings.Contains(subdomain, "..") {
		return false
	}

	if subdomain != domain && !strings.Contains(subdomain, ".") {
		return false
	}

	if strings.ContainsAny(subdomain, " \t\n\r") {
		return false
	}

	return true
}
