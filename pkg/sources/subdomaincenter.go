package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"samoscout/pkg/session"
	"strings"
)

type SubdomainCenter struct{}

type SubdomainCenterResponse []string

func (s *SubdomainCenter) Name() string {
	return "subdomaincenter"
}

func (s *SubdomainCenter) Run(ctx context.Context, domain string, sess *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		seen := make(map[string]bool)

		var url string
		if sess.Keys.SubdomainCenter != "" {
			url = fmt.Sprintf("https://api.subdomain.center/beta/?domain=%s&engine=cuttlefish&auth=%s", domain, sess.Keys.SubdomainCenter)
		} else {
			url = fmt.Sprintf("https://api.subdomain.center/?domain=%s&engine=cuttlefish", domain)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- Result{Source: s.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		req.Header.Set("Accept", "application/json")

		resp, err := sess.Client.Do(req)
		if err != nil {
			results <- Result{Source: s.Name(), Error: fmt.Errorf("failed to execute request: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			results <- Result{Source: s.Name(), Error: fmt.Errorf("authentication failed - invalid API key")}
			return
		}

		if resp.StatusCode == 429 {
			results <- Result{Source: s.Name(), Error: fmt.Errorf("rate limit exceeded - consider using an API key")}
			return
		}

		if resp.StatusCode != http.StatusOK {
			results <- Result{Source: s.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
			return
		}

		var response SubdomainCenterResponse
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			results <- Result{Source: s.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
			return
		}

		// Process subdomains
		for _, subdomain := range response {
			hostname := strings.TrimSpace(strings.ToLower(subdomain))

			if hostname != "" && !seen[hostname] {
				seen[hostname] = true

				select {
				case results <- Result{Source: s.Name(), Value: hostname, Type: "subdomain"}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return results
}
