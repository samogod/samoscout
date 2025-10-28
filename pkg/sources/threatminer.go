package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"github.com/samogod/samoscout/pkg/session"
	"strings"
)


type ThreatMiner struct{}


type ThreatMinerResponse struct {
	StatusCode    string   `json:"status_code"`
	StatusMessage string   `json:"status_message"`
	Results       []string `json:"results"`
}


func (t *ThreatMiner) Name() string {
	return "threatminer"
}


func (t *ThreatMiner) Run(ctx context.Context, domain string, session *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		seen := make(map[string]bool)
		url := fmt.Sprintf("https://api.threatminer.org/v2/domain.php?q=%s&rt=5", domain)
		
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

		var response ThreatMinerResponse
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			results <- Result{Source: t.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
			return
		}

		
		if response.StatusCode != "200" {
			results <- Result{Source: t.Name(), Error: fmt.Errorf("API returned status code: %s, message: %s", response.StatusCode, response.StatusMessage)}
			return
		}

		
		for _, subdomain := range response.Results {
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
