package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"github.com/samogod/samoscout/pkg/session"
	"strings"
)

type C99 struct{}

type C99Response struct {
	Success    bool `json:"success"`
	Subdomains []struct {
		Subdomain  string `json:"subdomain"`
		IP         string `json:"ip"`
		Cloudflare bool   `json:"cloudflare"`
	} `json:"subdomains"`
	Error string `json:"error"`
}

func (c *C99) Name() string {
	return "c99"
}

func (c *C99) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		if s.Keys.C99 == "" {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("C99 API key not configured")}
			return
		}

		url := fmt.Sprintf("https://api.c99.nl/subdomainfinder?key=%s&domain=%s&json", s.Keys.C99, domain)
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
			results <- Result{Source: c.Name(), Error: fmt.Errorf("invalid C99 API key")}
			return
		}

		if resp.StatusCode == 429 {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("C99 rate limit exceeded")}
			return
		}

		if resp.StatusCode != http.StatusOK {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
			return
		}

		var c99Resp C99Response
		if err := json.NewDecoder(resp.Body).Decode(&c99Resp); err != nil {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
			return
		}

		if c99Resp.Error != "" {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("API error: %s", c99Resp.Error)}
			return
		}

		if !c99Resp.Success {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("API returned success=false")}
			return
		}

		seen := make(map[string]bool)
		for _, data := range c99Resp.Subdomains {
			hostname := strings.TrimSpace(strings.ToLower(data.Subdomain))
			
			if !strings.HasPrefix(hostname, ".") && hostname != "" && strings.HasSuffix(hostname, "."+domain) && !seen[hostname] {
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
