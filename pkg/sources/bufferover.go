package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"samoscout/pkg/session"
	"strings"
)

type BufferOver struct{}

type BufferOverResponse struct {
	Meta struct {
		Errors []string `json:"Errors"`
	} `json:"Meta"`
	FDNSA   []string `json:"FDNS_A"`
	RDNS    []string `json:"RDNS"`
	Results []string `json:"Results"`
}

func (b *BufferOver) Name() string {
	return "bufferover"
}

func (b *BufferOver) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		if s.Keys.BufferOver == "" {
			results <- Result{Source: b.Name(), Error: fmt.Errorf("BufferOver API key not configured")}
			return
		}

		url := fmt.Sprintf("https://tls.bufferover.run/dns?q=.%s", domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- Result{Source: b.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		req.Header.Set("x-api-key", s.Keys.BufferOver)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		req.Header.Set("Accept", "application/json")

		resp, err := s.Client.Do(req)
		if err != nil {
			results <- Result{Source: b.Name(), Error: fmt.Errorf("failed to execute request: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == 401 {
			results <- Result{Source: b.Name(), Error: fmt.Errorf("invalid BufferOver API key")}
			return
		}

		if resp.StatusCode == 429 {
			results <- Result{Source: b.Name(), Error: fmt.Errorf("BufferOver rate limit exceeded")}
			return
		}

		if resp.StatusCode != http.StatusOK {
			results <- Result{Source: b.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
			return
		}

		var bufferoverResp BufferOverResponse
		if err := json.NewDecoder(resp.Body).Decode(&bufferoverResp); err != nil {
			results <- Result{Source: b.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
			return
		}

		if len(bufferoverResp.Meta.Errors) > 0 {
			results <- Result{Source: b.Name(), Error: fmt.Errorf("API errors: %s", strings.Join(bufferoverResp.Meta.Errors, ", "))}
			return
		}

		var allSubdomains []string
		if len(bufferoverResp.FDNSA) > 0 {
			allSubdomains = bufferoverResp.FDNSA
			allSubdomains = append(allSubdomains, bufferoverResp.RDNS...)
		} else if len(bufferoverResp.Results) > 0 {
			allSubdomains = bufferoverResp.Results
		}

		seen := make(map[string]bool)
		for _, subdomain := range allSubdomains {
			parts := strings.Fields(subdomain)
			for _, part := range parts {
				hostname := strings.TrimSpace(strings.ToLower(part))
				
				if hostname != "" && strings.HasSuffix(hostname, "."+domain) && !seen[hostname] {
					seen[hostname] = true
					
					select {
					case results <- Result{Source: b.Name(), Value: hostname, Type: "subdomain"}:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	return results
}
