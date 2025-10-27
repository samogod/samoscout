package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"samoscout/pkg/session"
	"strings"
)


type DNSDumpster struct{}


type DNSDumpsterResponse struct {
	A  []DNSDumpsterRecord `json:"a"`
	Ns []DNSDumpsterRecord `json:"ns"`
}

type DNSDumpsterRecord struct {
	Host string `json:"host"`
}


func (d *DNSDumpster) Name() string {
	return "dnsdumpster"
}


func (d *DNSDumpster) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		if s.Keys.DNSDumpster == "" {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("DNSDumpster API key not configured")}
			return
		}

		
		url := fmt.Sprintf("https://api.dnsdumpster.com/domain/%s", domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		
		req.Header.Set("X-API-Key", s.Keys.DNSDumpster)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		req.Header.Set("Accept", "application/json")

		resp, err := s.Client.Do(req)
		if err != nil {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("failed to execute request: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == 401 {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("invalid DNSDumpster API key")}
			return
		}

		if resp.StatusCode == 429 {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("DNSDumpster rate limit exceeded")}
			return
		}

		if resp.StatusCode != http.StatusOK {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
			return
		}

		
		var dnsResp DNSDumpsterResponse
		if err := json.NewDecoder(resp.Body).Decode(&dnsResp); err != nil {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
			return
		}

		
		allRecords := append(dnsResp.A, dnsResp.Ns...)
		seen := make(map[string]bool)
		
		for _, record := range allRecords {
			hostname := strings.TrimSpace(strings.ToLower(record.Host))
			
			
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
