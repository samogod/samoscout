package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"samoscout/pkg/session"
	"strings"
)

type AlienVault struct{}

type AlienVaultResponse struct {
	Detail     string `json:"detail"`
	Error      string `json:"error"`
	PassiveDNS []struct {
		Hostname string `json:"hostname"`
	} `json:"passive_dns"`
}

func (a *AlienVault) Name() string {
	return "alienvault"
}

func (a *AlienVault) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- Result{Source: a.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		req.Header.Set("Accept", "application/json")

		resp, err := s.Client.Do(req)
		if err != nil {
			results <- Result{Source: a.Name(), Error: fmt.Errorf("failed to execute request: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			results <- Result{Source: a.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
			return
		}

		var alienvaultResp AlienVaultResponse
		if err := json.NewDecoder(resp.Body).Decode(&alienvaultResp); err != nil {
			results <- Result{Source: a.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
			return
		}

		if alienvaultResp.Error != "" {
			results <- Result{Source: a.Name(), Error: fmt.Errorf("%s, %s", alienvaultResp.Detail, alienvaultResp.Error)}
			return
		}

		seen := make(map[string]bool)
		for _, record := range alienvaultResp.PassiveDNS {
			hostname := strings.TrimSpace(strings.ToLower(record.Hostname))
			
			if hostname != "" && strings.HasSuffix(hostname, "."+domain) && !seen[hostname] {
				seen[hostname] = true
				
				select {
				case results <- Result{Source: a.Name(), Value: hostname, Type: "subdomain"}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return results
}
