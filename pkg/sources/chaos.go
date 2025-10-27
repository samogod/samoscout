package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"samoscout/pkg/session"
	"strings"
)

type Chaos struct{}

type ChaosResponse struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
	Count      int      `json:"count"`
}

func (c *Chaos) Name() string {
	return "chaos"
}

func (c *Chaos) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		if s.Keys.Chaos == "" {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("Chaos API key not configured")}
			return
		}

		url := fmt.Sprintf("https://dns.projectdiscovery.io/dns/%s/subdomains", domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		req.Header.Set("Authorization", s.Keys.Chaos)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		req.Header.Set("Accept", "application/json")

		resp, err := s.Client.Do(req)
		if err != nil {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("failed to execute request: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == 401 {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("invalid Chaos API key")}
			return
		}

		if resp.StatusCode == 429 {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("Chaos rate limit exceeded")}
			return
		}

		if resp.StatusCode != http.StatusOK {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
			return
		}

		var chaosResp ChaosResponse
		if err := json.NewDecoder(resp.Body).Decode(&chaosResp); err != nil {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
			return
		}

		seen := make(map[string]bool)
		for _, subdomain := range chaosResp.Subdomains {
			cleanSub := strings.TrimSpace(strings.ToLower(subdomain))
			
			var fullSubdomain string
			if strings.Contains(cleanSub, ".") {
				fullSubdomain = cleanSub
			} else {
				fullSubdomain = fmt.Sprintf("%s.%s", cleanSub, domain)
			}
			
			if fullSubdomain != "" && fullSubdomain != domain && strings.HasSuffix(fullSubdomain, "."+domain) && !seen[fullSubdomain] {
				seen[fullSubdomain] = true

				select {
				case results <- Result{Source: c.Name(), Value: fullSubdomain, Type: "subdomain"}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return results
}
