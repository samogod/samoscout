package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"samoscout/pkg/session"
	"strings"
)


type ThreatCrowd struct{}


type ThreatCrowdResponse struct {
	ResponseCode string   `json:"response_code"`
	Subdomains   []string `json:"subdomains"`
	Undercount   string   `json:"undercount"`
}


func (t *ThreatCrowd) Name() string {
	return "threatcrowd"
}


func (t *ThreatCrowd) Run(ctx context.Context, domain string, session *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		seen := make(map[string]bool)
		url := fmt.Sprintf("http://ci-www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s", domain)
		
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- Result{Source: t.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

		resp, err := session.Client.Do(req)
		if err != nil {
			results <- Result{Source: t.Name(), Error: fmt.Errorf("API request failed: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			results <- Result{Source: t.Name(), Error: fmt.Errorf("unexpected status code: %d", resp.StatusCode)}
			return
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			results <- Result{Source: t.Name(), Error: fmt.Errorf("failed to read response body: %w", err)}
			return
		}

		var response ThreatCrowdResponse
		if err := json.Unmarshal(body, &response); err != nil {
			results <- Result{Source: t.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
			return
		}

		
		if response.ResponseCode != "1" {
			results <- Result{Source: t.Name(), Error: fmt.Errorf("API returned response code: %s", response.ResponseCode)}
			return
		}

		
		for _, subdomain := range response.Subdomains {
			hostname := strings.TrimSpace(strings.ToLower(subdomain))
			
			if hostname != "" && !seen[hostname] {
				seen[hostname] = true

				select {
				case results <- Result{Source: t.Name(), Value: hostname, Type: "subdomain"}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return results
}
