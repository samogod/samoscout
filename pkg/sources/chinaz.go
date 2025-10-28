package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"github.com/samogod/samoscout/pkg/session"
	"strings"
)

type Chinaz struct{}

type ChinazResponse struct {
	StateCode int `json:"StateCode"`
	Reason    string `json:"Reason"`
	Result    ChinazResult `json:"Result"`
}

type ChinazResult struct {
	ContributingSubdomainList []ChinazSubdomain `json:"ContributingSubdomainList"`
	Domain                    string            `json:"Domain"`
	AlexaRank                 int               `json:"AlexaRank"`
}

type ChinazSubdomain struct {
	DataUrl     string  `json:"DataUrl"`
	Percent     float64 `json:"Percent"`
}

func (c *Chinaz) Name() string {
	return "chinaz"
}

func (c *Chinaz) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		if s.Keys.Chinaz == "" {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("Chinaz API key not configured")}
			return
		}

		url := fmt.Sprintf("https://apidatav2.chinaz.com/single/alexa?key=%s&domain=%s", s.Keys.Chinaz, domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		req.Header.Set("Accept", "application/json")

		resp, err := s.Client.Do(req)
		if err != nil {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("failed to execute request: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == 401 {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("invalid Chinaz API key")}
			return
		}

		if resp.StatusCode == 429 {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("Chinaz rate limit exceeded")}
			return
		}

		if resp.StatusCode != http.StatusOK {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
			return
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("failed to read response body: %w", err)}
			return
		}

		var chinazResp ChinazResponse
		if err := json.Unmarshal(body, &chinazResp); err != nil {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
			return
		}

		if chinazResp.StateCode != 0 {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("API error: %s (StateCode: %d)", chinazResp.Reason, chinazResp.StateCode)}
			return
		}

		seen := make(map[string]bool)
		for _, subdomain := range chinazResp.Result.ContributingSubdomainList {
			hostname := strings.TrimSpace(strings.ToLower(subdomain.DataUrl))
			
			if hostname != "" && hostname != domain && strings.HasSuffix(hostname, "."+domain) && !seen[hostname] {
				seen[hostname] = true

				select {
				case results <- Result{Source: c.Name(), Value: hostname, Type: "subdomain"}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return results
}
