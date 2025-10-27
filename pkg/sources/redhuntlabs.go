package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"samoscout/pkg/session"
	"strings"
)

type RedHuntLabs struct{}

type RedHuntLabsResponse struct {
	Subdomains []string            `json:"subdomains"`
	Metadata   RedHuntLabsMetadata `json:"metadata"`
}

type RedHuntLabsMetadata struct {
	ResultCount int `json:"result_count"`
	PageSize    int `json:"page_size"`
	PageNumber  int `json:"page_number"`
}

func (r *RedHuntLabs) Name() string {
	return "redhuntlabs"
}

func (r *RedHuntLabs) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		if s.Keys.RedHuntLabs == "" {
			results <- Result{Source: r.Name(), Error: fmt.Errorf("RedHuntLabs API key not configured")}
			return
		}

		if !strings.Contains(s.Keys.RedHuntLabs, ":") {
			results <- Result{Source: r.Name(), Error: fmt.Errorf("RedHuntLabs API key format should be baseurl:port:apikey")}
			return
		}

		apiKeyParts := strings.Split(s.Keys.RedHuntLabs, ":")
		if len(apiKeyParts) != 3 {
			results <- Result{Source: r.Name(), Error: fmt.Errorf("RedHuntLabs API key format should be baseurl:port:apikey")}
			return
		}

		baseURL := apiKeyParts[0] + ":" + apiKeyParts[1]
		apiKey := apiKeyParts[2]
		pageSize := 1000

		page := 1
		url := fmt.Sprintf("%s?domain=%s&page=%d&page_size=%d", baseURL, domain, page, pageSize)

		response, err := r.makeRequest(ctx, url, apiKey, s)
		if err != nil {
			results <- Result{Source: r.Name(), Error: err}
			return
		}

		seen := make(map[string]bool)

		for _, subdomain := range response.Subdomains {
			hostname := strings.TrimSpace(strings.ToLower(subdomain))

			if hostname != "" && hostname != domain &&
				strings.HasSuffix(hostname, "."+domain) &&
				r.isValidHostname(hostname) && !seen[hostname] {
				seen[hostname] = true

				select {
				case results <- Result{Source: r.Name(), Value: hostname, Type: "subdomain"}:
				case <-ctx.Done():
					return
				}
			}
		}

		if response.Metadata.ResultCount > pageSize {
			totalPages := (response.Metadata.ResultCount + pageSize - 1) / pageSize

			for page := 2; page <= totalPages; page++ {
				select {
				case <-ctx.Done():
					return
				default:
				}

				url := fmt.Sprintf("%s?domain=%s&page=%d&page_size=%d", baseURL, domain, page, pageSize)

				pageResponse, err := r.makeRequest(ctx, url, apiKey, s)
				if err != nil {
					results <- Result{Source: r.Name(), Error: fmt.Errorf("error on page %d: %w", page, err)}
					continue
				}

				for _, subdomain := range pageResponse.Subdomains {
					hostname := strings.TrimSpace(strings.ToLower(subdomain))

					if hostname != "" && hostname != domain &&
						strings.HasSuffix(hostname, "."+domain) &&
						r.isValidHostname(hostname) && !seen[hostname] {
						seen[hostname] = true

						select {
						case results <- Result{Source: r.Name(), Value: hostname, Type: "subdomain"}:
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

func (r *RedHuntLabs) makeRequest(ctx context.Context, url, apiKey string, s *session.Session) (*RedHuntLabsResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-BLOBR-KEY", apiKey)

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("invalid RedHuntLabs API key")
	}

	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("RedHuntLabs rate limit exceeded - visit https://devportal.redhuntlabs.com")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %d - visit https://devportal.redhuntlabs.com if limit reached", resp.StatusCode)
	}

	var response RedHuntLabsResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %w", err)
	}

	return &response, nil
}

func (r *RedHuntLabs) isValidHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}

	if strings.HasPrefix(hostname, ".") || strings.HasSuffix(hostname, ".") {
		return false
	}

	if strings.Contains(hostname, "..") {
		return false
	}

	if !strings.Contains(hostname, ".") {
		return false
	}

	for _, char := range hostname {
		if !((char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') ||
			char == '-' || char == '.') {
			return false
		}
	}

	if strings.HasPrefix(hostname, "-") || strings.HasSuffix(hostname, "-") {
		return false
	}

	if strings.Contains(hostname, "--") {
		return false
	}

	return true
}
