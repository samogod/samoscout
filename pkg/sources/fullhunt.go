package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"samoscout/pkg/session"
	"strings"
)


type FullHunt struct{}


type FullHuntResponse struct {
	Hosts   []string `json:"hosts"`
	Message string   `json:"message"`
	Status  int      `json:"status"`
}


func (f *FullHunt) Name() string {
	return "fullhunt"
}


func (f *FullHunt) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		if s.Keys.FullHunt == "" {
			results <- Result{Source: f.Name(), Error: fmt.Errorf("FullHunt API key not configured")}
			return
		}

		
		url := fmt.Sprintf("https://fullhunt.io/api/v1/domain/%s/subdomains", domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- Result{Source: f.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		
		req.Header.Set("X-API-KEY", s.Keys.FullHunt)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		req.Header.Set("Accept", "application/json")

		resp, err := s.Client.Do(req)
		if err != nil {
			results <- Result{Source: f.Name(), Error: fmt.Errorf("failed to execute request: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == 401 {
			results <- Result{Source: f.Name(), Error: fmt.Errorf("invalid FullHunt API key")}
			return
		}

		if resp.StatusCode == 429 {
			results <- Result{Source: f.Name(), Error: fmt.Errorf("FullHunt rate limit exceeded")}
			return
		}

		if resp.StatusCode != http.StatusOK {
			results <- Result{Source: f.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
			return
		}

		
		var fullHuntResp FullHuntResponse
		if err := json.NewDecoder(resp.Body).Decode(&fullHuntResp); err != nil {
			results <- Result{Source: f.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
			return
		}

		
		if fullHuntResp.Status != 200 && fullHuntResp.Status != 0 {
			results <- Result{Source: f.Name(), Error: fmt.Errorf("FullHunt API error: %s (status: %d)", fullHuntResp.Message, fullHuntResp.Status)}
			return
		}

		
		seen := make(map[string]bool)
		for _, host := range fullHuntResp.Hosts {
			hostname := strings.TrimSpace(strings.ToLower(host))
			
			
			if hostname != "" && hostname != domain && strings.HasSuffix(hostname, "."+domain) && !seen[hostname] {
				seen[hostname] = true

				select {
				case results <- Result{Source: f.Name(), Value: hostname, Type: "subdomain"}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return results
}
