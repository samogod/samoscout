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

type DNSArchive struct{}

type DNSArchiveResponse []struct {
	Domain string `json:"domain"`
}

func (d *DNSArchive) Name() string {
	return "DNSArchive"
}

func (d *DNSArchive) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		if s.Keys.DNSArchive == "" {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("DNSArchive API key not configured")}
			return
		}

		apiKeyParts := strings.Split(s.Keys.DNSArchive, ":")
		if len(apiKeyParts) != 2 {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("DNSArchive API key must be in format 'token:apikey'")}
			return
		}

		token := apiKeyParts[0]
		apiKey := apiKeyParts[1]

		url := fmt.Sprintf("https://dnsarchive.net/api/?apikey=%s&search=%s", apiKey, domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		req.Header.Set("X-API-Access", token)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		req.Header.Set("Accept", "application/json")

		resp, err := s.Client.Do(req)
		if err != nil {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("failed to execute request: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == 401 {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("invalid DNSArchive API credentials")}
			return
		}

		if resp.StatusCode == 429 {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("DNSArchive rate limit exceeded")}
			return
		}

		if resp.StatusCode != http.StatusOK {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
			return
		}

		responseData, err := io.ReadAll(resp.Body)
		if err != nil {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("failed to read response body: %w", err)}
			return
		}

		var DNSArchiveResp DNSArchiveResponse
		if err := json.Unmarshal(responseData, &DNSArchiveResp); err != nil {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
			return
		}

		seen := make(map[string]bool)
		for _, record := range DNSArchiveResp {

			hostname := strings.TrimSuffix(record.Domain, ".")
			hostname = strings.TrimSpace(strings.ToLower(hostname))

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
