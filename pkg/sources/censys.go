package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"samoscout/pkg/session"
	"strconv"
	"strings"
)

type Censys struct{}

type CensysResponse struct {
	Result CensysResult `json:"result"`
	Status string       `json:"status"`
}

type CensysResult struct {
	Query      string      `json:"query"`
	Total      int         `json:"total"`
	DurationMS int         `json:"duration_ms"`
	Hits       []CensysHit `json:"hits"`
	Links      CensysLinks `json:"links"`
}

type CensysHit struct {
	Parsed            CensysParsed `json:"parsed"`
	Names             []string     `json:"names"`
	FingerprintSha256 string       `json:"fingerprint_sha256"`
}

type CensysParsed struct {
	ValidityPeriod CensysValidityPeriod `json:"validity_period"`
	SubjectDN      string               `json:"subject_dn"`
	IssuerDN       string               `json:"issuer_dn"`
}

type CensysValidityPeriod struct {
	NotAfter  string `json:"not_after"`
	NotBefore string `json:"not_before"`
}

type CensysLinks struct {
	Next string `json:"next"`
	Prev string `json:"prev"`
}

const (
	maxCensysPages = 10
	maxPerPage     = 100
)

func (c *Censys) Name() string {
	return "censys"
}

func (c *Censys) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		if s.Keys.Censys == "" {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("Censys API key not configured")}
			return
		}

		cursor := ""
		currentPage := 1

		for {
			baseURL := "https://api.platform.censys.io/v3/global/search/certificates"
			u, err := url.Parse(baseURL)
			if err != nil {
				results <- Result{Source: c.Name(), Error: fmt.Errorf("failed to parse URL: %w", err)}
				return
			}

			params := u.Query()
			params.Add("q", fmt.Sprintf("names: *.%s", domain))
			params.Add("per_page", strconv.Itoa(maxPerPage))
			if cursor != "" {
				params.Add("cursor", cursor)
			}
			u.RawQuery = params.Encode()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
			if err != nil {
				results <- Result{Source: c.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
				return
			}

			req.Header.Set("Authorization", "Bearer "+s.Keys.Censys)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
			req.Header.Set("Accept", "application/vnd.censys.api.v3.certificate.v1+json")

			resp, err := s.Client.Do(req)
			if err != nil {
				results <- Result{Source: c.Name(), Error: fmt.Errorf("failed to execute request: %w", err)}
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == 401 {
				results <- Result{Source: c.Name(), Error: fmt.Errorf("invalid Censys API credentials")}
				return
			}

			if resp.StatusCode == 429 {
				results <- Result{Source: c.Name(), Error: fmt.Errorf("Censys rate limit exceeded")}
				return
			}

			if resp.StatusCode != http.StatusOK {
				results <- Result{Source: c.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
				return
			}

			var censysResp CensysResponse
			if err := json.NewDecoder(resp.Body).Decode(&censysResp); err != nil {
				results <- Result{Source: c.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
				return
			}

			seen := make(map[string]bool)
			for _, hit := range censysResp.Result.Hits {
				for _, name := range hit.Names {
					hostname := strings.TrimSpace(strings.ToLower(name))
					
					if hostname != "" && strings.HasSuffix(hostname, "."+domain) && !seen[hostname] {
						seen[hostname] = true
						
						select {
						case results <- Result{Source: c.Name(), Value: hostname, Type: "subdomain"}:
						case <-ctx.Done():
							return
						}
					}
				}
			}

			cursor = censysResp.Result.Links.Next
			if cursor == "" || currentPage >= maxCensysPages {
				break
			}
			currentPage++
		}
	}()

	return results
}
