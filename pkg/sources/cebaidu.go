package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"samoscout/pkg/session"
	"strings"
)

type Cebaidu struct{}

type domain struct {
	Domain string `json:"domain"`
}

type cebaiduResponse struct {
	Code    int64    `json:"code"`
	Message string   `json:"message"`
	Data    []domain `json:"data"`
}

func (c *Cebaidu) Name() string {
	return "cebaidu"
}

func (c *Cebaidu) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		url := fmt.Sprintf("https://ce.baidu.com/index/getRelatedSites?site_address=%s", domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		req.Header.Set("Accept", "application/json")

		resp, err := s.Client.Do(req)
		if err != nil {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("API request failed: %w", err)}
			return
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			results <- Result{Source: c.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
			return
		}

		var response cebaiduResponse
		err = json.NewDecoder(resp.Body).Decode(&response)
		resp.Body.Close()
		if err != nil {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
			return
		}

		if response.Code > 0 {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("API error: %d, %s", response.Code, response.Message)}
			return
		}

		seen := make(map[string]bool)
		for _, domainResult := range response.Data {
			hostname := strings.TrimSpace(strings.ToLower(domainResult.Domain))
			
			if hostname != "" && !seen[hostname] {
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
