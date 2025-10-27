package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"samoscout/pkg/session"
	"strings"
)


type Shodan struct{}


type ShodanResponse struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
	Result     int      `json:"result"`
	Error      string   `json:"error"`
	More       bool     `json:"more"`
}


func (s *Shodan) Name() string {
	return "shodan"
}


func (s *Shodan) Run(ctx context.Context, domain string, session *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		if session.Keys.Shodan == "" {
			results <- Result{Source: s.Name(), Error: fmt.Errorf("Shodan API key not configured")}
			return
		}

		seen := make(map[string]bool)
		page := 1

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			searchURL := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s&page=%d", domain, session.Keys.Shodan, page)
			
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, nil)
			if err != nil {
				results <- Result{Source: s.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
				return
			}

			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

			resp, err := session.Client.Do(req)
			if err != nil {
				results <- Result{Source: s.Name(), Error: fmt.Errorf("API request failed: %w", err)}
				return
			}

			var response ShodanResponse
			if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
				resp.Body.Close()
				results <- Result{Source: s.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
				return
			}
			resp.Body.Close()

			if response.Error != "" {
				results <- Result{Source: s.Name(), Error: fmt.Errorf("API error: %s", response.Error)}
				return
			}

			
			for _, subdomain := range response.Subdomains {
				
				var fullDomain string
				if strings.HasSuffix(subdomain, ".") {
					fullDomain = subdomain + response.Domain
				} else {
					fullDomain = subdomain + "." + response.Domain
				}

				hostname := strings.TrimSpace(strings.ToLower(fullDomain))
				
				if hostname != "" && !seen[hostname] {
					seen[hostname] = true

					select {
					case results <- Result{Source: s.Name(), Value: hostname, Type: "subdomain"}:
					case <-ctx.Done():
						return
					}
				}
			}

			if !response.More {
				break
			}
			page++
		}
	}()

	return results
}
