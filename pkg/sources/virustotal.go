package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"github.com/samogod/samoscout/pkg/session"
	"strings"
)


type VirusTotal struct{}


type VirusTotalResponse struct {
	Data []struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"data"`
	Meta struct {
		Cursor string `json:"cursor"`
	} `json:"meta"`
}


func (v *VirusTotal) Name() string {
	return "virustotal"
}


func (v *VirusTotal) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		if s.Keys.VirusTotal == "" {
			results <- Result{Source: v.Name(), Error: fmt.Errorf("VirusTotal API key not configured")}
			return
		}

		seen := make(map[string]bool)
		cursor := ""

		
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			
			url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=40", domain)
			if cursor != "" {
				url = fmt.Sprintf("%s&cursor=%s", url, cursor)
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				results <- Result{Source: v.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
				return
			}

			
			req.Header.Set("x-apikey", s.Keys.VirusTotal)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
			req.Header.Set("Accept", "application/json")

			resp, err := s.Client.Do(req)
			if err != nil {
				results <- Result{Source: v.Name(), Error: fmt.Errorf("failed to execute request: %w", err)}
				return
			}

			if resp.StatusCode == 401 {
				resp.Body.Close()
				results <- Result{Source: v.Name(), Error: fmt.Errorf("invalid VirusTotal API key")}
				return
			}

			if resp.StatusCode == 429 {
				resp.Body.Close()
				results <- Result{Source: v.Name(), Error: fmt.Errorf("VirusTotal rate limit exceeded")}
				return
			}

			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				results <- Result{Source: v.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
				return
			}

			
			var vtResp VirusTotalResponse
			if err := json.NewDecoder(resp.Body).Decode(&vtResp); err != nil {
				resp.Body.Close()
				results <- Result{Source: v.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
				return
			}
			resp.Body.Close()

			
			for _, item := range vtResp.Data {
				hostname := strings.TrimSpace(strings.ToLower(item.ID))
				
				if hostname != "" && !seen[hostname] {
					seen[hostname] = true
					
					select {
					case results <- Result{Source: v.Name(), Value: hostname, Type: "subdomain"}:
					case <-ctx.Done():
						return
					}
				}
			}

			
			cursor = vtResp.Meta.Cursor
			if cursor == "" {
				break
			}
		}
	}()

	return results
}
