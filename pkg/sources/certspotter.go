package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"github.com/samogod/samoscout/pkg/session"
	"strings"
)


type CertSpotter struct{}


type CertSpotterObject struct {
	ID       string   `json:"id"`
	DNSNames []string `json:"dns_names"`
}


func (c *CertSpotter) Name() string {
	return "certspotter"
}


func (c *CertSpotter) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		if s.Keys.CertSpotter == "" {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("CertSpotter API key not configured")}
			return
		}

		url := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain)
		response, err := c.makeRequest(ctx, url, s)
		if err != nil {
			results <- Result{Source: c.Name(), Error: err}
			return
		}

		seen := make(map[string]bool)
		c.processResults(response, domain, seen, results)

		if len(response) == 0 {
			return
		}

		lastID := response[len(response)-1].ID
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			nextURL := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names&after=%s", domain, lastID)
			response, err := c.makeRequest(ctx, nextURL, s)
			if err != nil {
				results <- Result{Source: c.Name(), Error: err}
				return
			}

			if len(response) == 0 {
				break
			}

			c.processResults(response, domain, seen, results)

			lastID = response[len(response)-1].ID
		}
	}()

	return results
}

func (c *CertSpotter) makeRequest(ctx context.Context, url string, s *session.Session) ([]CertSpotterObject, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+s.Keys.CertSpotter)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "application/json")

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("invalid CertSpotter API key")
	}

	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("CertSpotter rate limit exceeded")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	var response []CertSpotterObject
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %w", err)
	}

	return response, nil
}

func (c *CertSpotter) processResults(response []CertSpotterObject, domain string, seen map[string]bool, results chan<- Result) {
	for _, cert := range response {
		for _, dnsName := range cert.DNSNames {
			hostname := strings.TrimSpace(strings.ToLower(dnsName))
			
			if hostname != "" && strings.HasSuffix(hostname, "."+domain) && !seen[hostname] {
				seen[hostname] = true
				
				select {
				case results <- Result{Source: c.Name(), Value: hostname, Type: "subdomain"}:
				default:
				}
			}
		}
	}
}
