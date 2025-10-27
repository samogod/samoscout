package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"samoscout/pkg/session"
	"strings"
)


type WhoisXMLAPI struct{}


type WhoisXMLAPIResponse struct {
	Search string                    `json:"search"`
	Result WhoisXMLAPIResponseResult `json:"result"`
}

type WhoisXMLAPIResponseResult struct {
	Count   int                      `json:"count"`
	Records []WhoisXMLAPIResponseRecord `json:"records"`
}

type WhoisXMLAPIResponseRecord struct {
	Domain    string `json:"domain"`
	FirstSeen int    `json:"firstSeen"`
	LastSeen  int    `json:"lastSeen"`
}


func (w *WhoisXMLAPI) Name() string {
	return "whoisxmlapi"
}


func (w *WhoisXMLAPI) Run(ctx context.Context, domain string, session *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		if session.Keys.WhoisXMLAPI == "" {
			results <- Result{Source: w.Name(), Error: fmt.Errorf("WhoisXMLAPI API key not configured")}
			return
		}

		seen := make(map[string]bool)
		apiURL := fmt.Sprintf("https://subdomains.whoisxmlapi.com/api/v1?apiKey=%s&domainName=%s", session.Keys.WhoisXMLAPI, domain)
		
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
		if err != nil {
			results <- Result{Source: w.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

		resp, err := session.Client.Do(req)
		if err != nil {
			results <- Result{Source: w.Name(), Error: fmt.Errorf("API request failed: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == 401 {
			results <- Result{Source: w.Name(), Error: fmt.Errorf("invalid WhoisXMLAPI API key")}
			return
		}

		if resp.StatusCode == 429 {
			results <- Result{Source: w.Name(), Error: fmt.Errorf("WhoisXMLAPI rate limit exceeded")}
			return
		}

		if resp.StatusCode != http.StatusOK {
			results <- Result{Source: w.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
			return
		}

		var response WhoisXMLAPIResponse
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			results <- Result{Source: w.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
			return
		}

		
		for _, record := range response.Result.Records {
			hostname := strings.TrimSpace(strings.ToLower(record.Domain))
			
			if hostname != "" && !seen[hostname] {
				seen[hostname] = true

				select {
				case results <- Result{Source: w.Name(), Value: hostname, Type: "subdomain"}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return results
}
