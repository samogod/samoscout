package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"samoscout/pkg/session"
	"strings"
)

type BeVigil struct{}

type BeVigilResponse struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
}

func (b *BeVigil) Name() string {
	return "bevigil"
}

func (b *BeVigil) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		if s.Keys.BeVigil == "" {
			results <- Result{Source: b.Name(), Error: fmt.Errorf("BeVigil API key not configured")}
			return
		}

		url := fmt.Sprintf("https://osint.bevigil.com/api/%s/subdomains/", domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- Result{Source: b.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		req.Header.Set("X-Access-Token", s.Keys.BeVigil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		req.Header.Set("Accept", "application/json")

		resp, err := s.Client.Do(req)
		if err != nil {
			results <- Result{Source: b.Name(), Error: fmt.Errorf("failed to execute request: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == 401 {
			results <- Result{Source: b.Name(), Error: fmt.Errorf("invalid BeVigil API key")}
			return
		}

		if resp.StatusCode == 429 {
			results <- Result{Source: b.Name(), Error: fmt.Errorf("BeVigil rate limit exceeded")}
			return
		}

		if resp.StatusCode != http.StatusOK {
			results <- Result{Source: b.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
			return
		}

		var bevigilResp BeVigilResponse
		if err := json.NewDecoder(resp.Body).Decode(&bevigilResp); err != nil {
			results <- Result{Source: b.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
			return
		}

		seen := make(map[string]bool)
		for _, subdomain := range bevigilResp.Subdomains {
			hostname := strings.TrimSpace(strings.ToLower(subdomain))
			
			if hostname != "" && strings.HasSuffix(hostname, "."+domain) && !seen[hostname] {
				seen[hostname] = true
				
				select {
				case results <- Result{Source: b.Name(), Value: hostname, Type: "subdomain"}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return results
}
