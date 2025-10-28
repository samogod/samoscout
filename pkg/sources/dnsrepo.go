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

type DNSRepo struct{}

type dnsRepoResponse []struct {
	Domain string `json:"domain"`
}

func (d *DNSRepo) Name() string {
	return "dnsrepo"
}

func (d *DNSRepo) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		if s.Keys.DNSRepo == "" {
			return
		}

		apiURL := fmt.Sprintf("https://dnsrepo.noc.org/api/?apikey=%s&search=%s", s.Keys.DNSRepo, domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
		if err != nil {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "application/json")

		resp, err := s.Client.Do(req)
		if err != nil {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("request failed: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
			return
		}

		responseData, err := io.ReadAll(resp.Body)
		if err != nil {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("failed to read response: %w", err)}
			return
		}

		var result dnsRepoResponse
		if err := json.Unmarshal(responseData, &result); err != nil {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
			return
		}

		seen := make(map[string]bool)
		for _, sub := range result {
			hostname := strings.TrimSpace(strings.ToLower(strings.TrimSuffix(sub.Domain, ".")))

			if hostname != "" && !seen[hostname] {
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
