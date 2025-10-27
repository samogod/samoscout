package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"samoscout/pkg/session"
	"strings"
)

type BuiltWith struct{}

type BuiltWithResponse struct {
	Results []BuiltWithResultItem `json:"Results"`
}

type BuiltWithResultItem struct {
	Result BuiltWithResult `json:"Result"`
}

type BuiltWithResult struct {
	Paths []BuiltWithPath `json:"Paths"`
}

type BuiltWithPath struct {
	Domain    string `json:"Domain"`
	URL       string `json:"Url"`
	SubDomain string `json:"SubDomain"`
}

func (b *BuiltWith) Name() string {
	return "builtwith"
}

func (b *BuiltWith) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		if s.Keys.BuiltWith == "" {
			results <- Result{Source: b.Name(), Error: fmt.Errorf("BuiltWith API key not configured")}
			return
		}

		url := fmt.Sprintf("https://api.builtwith.com/v21/api.json?KEY=%s&HIDETEXT=yes&HIDEDL=yes&NOLIVE=yes&NOMETA=yes&NOPII=yes&NOATTR=yes&LOOKUP=%s", s.Keys.BuiltWith, domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- Result{Source: b.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		req.Header.Set("Accept", "application/json")

		resp, err := s.Client.Do(req)
		if err != nil {
			results <- Result{Source: b.Name(), Error: fmt.Errorf("failed to execute request: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == 401 {
			results <- Result{Source: b.Name(), Error: fmt.Errorf("invalid BuiltWith API key")}
			return
		}

		if resp.StatusCode == 429 {
			results <- Result{Source: b.Name(), Error: fmt.Errorf("BuiltWith rate limit exceeded")}
			return
		}

		if resp.StatusCode != http.StatusOK {
			results <- Result{Source: b.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
			return
		}

		var builtwithResp BuiltWithResponse
		if err := json.NewDecoder(resp.Body).Decode(&builtwithResp); err != nil {
			results <- Result{Source: b.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
			return
		}

		seen := make(map[string]bool)
		for _, result := range builtwithResp.Results {
			for _, path := range result.Result.Paths {
				if path.SubDomain != "" && path.Domain != "" {
					hostname := fmt.Sprintf("%s.%s", path.SubDomain, path.Domain)
					hostname = strings.TrimSpace(strings.ToLower(hostname))
					
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
		}
	}()

	return results
}
