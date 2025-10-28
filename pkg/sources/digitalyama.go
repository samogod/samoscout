package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"github.com/samogod/samoscout/pkg/session"
	"strings"
)


type DigitalYama struct{}


type DigitalYamaResponse struct {
	Query        string   `json:"query"`
	Count        int      `json:"count"`
	Subdomains   []string `json:"subdomains"`
	UsageSummary struct {
		QueryCost        float64 `json:"query_cost"`
		CreditsRemaining float64 `json:"credits_remaining"`
	} `json:"usage_summary"`
}


type DigitalYamaErrorResponse struct {
	Detail []struct {
		Loc  []string `json:"loc"`
		Msg  string   `json:"msg"`
		Type string   `json:"type"`
	} `json:"detail"`
}


func (d *DigitalYama) Name() string {
	return "digitalyama"
}


func (d *DigitalYama) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		if s.Keys.DigitalYama == "" {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("DigitalYama API key not configured")}
			return
		}

		
		url := fmt.Sprintf("https://api.digitalyama.com/subdomain_finder?domain=%s", domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		
		req.Header.Set("x-api-key", s.Keys.DigitalYama)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		req.Header.Set("Accept", "application/json")

		resp, err := s.Client.Do(req)
		if err != nil {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("failed to execute request: %w", err)}
			return
		}
		defer resp.Body.Close()

		
		if resp.StatusCode != http.StatusOK {
			var errResponse DigitalYamaErrorResponse
			if err := json.NewDecoder(resp.Body).Decode(&errResponse); err != nil {
				results <- Result{Source: d.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
				return
			}

			if len(errResponse.Detail) > 0 {
				errMsg := errResponse.Detail[0].Msg
				results <- Result{Source: d.Name(), Error: fmt.Errorf("%s (HTTP %d)", errMsg, resp.StatusCode)}
			} else {
				results <- Result{Source: d.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
			}
			return
		}

		
		var digitalYamaResp DigitalYamaResponse
		if err := json.NewDecoder(resp.Body).Decode(&digitalYamaResp); err != nil {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
			return
		}

		
		seen := make(map[string]bool)
		for _, subdomain := range digitalYamaResp.Subdomains {
			hostname := strings.TrimSpace(strings.ToLower(subdomain))
			
			
			if hostname != "" && hostname != domain && strings.HasSuffix(hostname, "."+domain) && !seen[hostname] {
				seen[hostname] = true

				select {
				case results <- Result{Source: d.Name(), Value: hostname, Type: "subdomain"}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return results
}
