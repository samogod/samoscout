package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"github.com/samogod/samoscout/pkg/session"
	"strings"
)

type MySSL struct{}

type MySSLResponse struct {
	Code  int              `json:"code"`
	Error string           `json:"error"`
	Data  []MySSLSubdomain `json:"data"`
}

type MySSLSubdomain struct {
	Domain string `json:"domain"`
}

func (m *MySSL) Name() string {
	return "myssl"
}

func (m *MySSL) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		url := fmt.Sprintf("https://myssl.com/api/v1/discover_sub_domain?domain=%s", domain)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- Result{Source: m.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		req.Header.Set("Accept", "application/json")

		resp, err := s.Client.Do(req)
		if err != nil {
			results <- Result{Source: m.Name(), Error: fmt.Errorf("failed to execute request: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == 429 {
			results <- Result{Source: m.Name(), Error: fmt.Errorf("MySSL rate limit exceeded")}
			return
		}

		if resp.StatusCode != http.StatusOK {
			results <- Result{Source: m.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
			return
		}

		var myssLResponse MySSLResponse
		if err := json.NewDecoder(resp.Body).Decode(&myssLResponse); err != nil {
			results <- Result{Source: m.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
			return
		}
		
		if myssLResponse.Code != 0 {
			if len(myssLResponse.Data) == 0 {
				results <- Result{Source: m.Name(), Error: fmt.Errorf("API error: %s", myssLResponse.Error)}
				return
			}
		}

		seen := make(map[string]bool)

		for _, subdomainData := range myssLResponse.Data {
			subdomain := strings.TrimSpace(strings.ToLower(subdomainData.Domain))

			if m.isValidSubdomain(subdomain, domain) && !seen[subdomain] {
				seen[subdomain] = true

				select {
				case results <- Result{Source: m.Name(), Value: subdomain, Type: "subdomain"}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return results
}

func (m *MySSL) isValidSubdomain(subdomain, domain string) bool {
	if subdomain == "" || subdomain == domain {
		return false
	}

	if !strings.HasSuffix(subdomain, "."+domain) && subdomain != domain {
		return false
	}

	if len(subdomain) == 0 || len(subdomain) > 253 {
		return false
	}

	if strings.HasPrefix(subdomain, ".") || strings.HasSuffix(subdomain, ".") {
		return false
	}

	if strings.Contains(subdomain, "..") {
		return false
	}

	if subdomain != domain && !strings.Contains(subdomain, ".") {
		return false
	}

	if strings.ContainsAny(subdomain, " \t\n\r") {
		return false
	}

	return true
}

