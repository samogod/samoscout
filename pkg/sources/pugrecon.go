package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"github.com/samogod/samoscout/pkg/session"
	"strings"
)


type PugRecon struct{}


type PugReconResult struct {
	Name string `json:"name"`
}


type PugReconAPIResponse struct {
	Results        []PugReconResult `json:"results"`
	QuotaRemaining int              `json:"quota_remaining"`
	Limited        bool             `json:"limited"`
	TotalResults   int              `json:"total_results"`
	Message        string           `json:"message"`
}


func (p *PugRecon) Name() string {
	return "pugrecon"
}


func (p *PugRecon) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		if s.Keys.PugRecon == "" {
			results <- Result{Source: p.Name(), Error: fmt.Errorf("PugRecon API key not configured")}
			return
		}

		
		postData := map[string]string{"domain_name": domain}
		bodyBytes, err := json.Marshal(postData)
		if err != nil {
			results <- Result{Source: p.Name(), Error: fmt.Errorf("failed to marshal request body: %w", err)}
			return
		}

		
		apiURL := "https://pugrecon.com/api/v1/domains"
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(bodyBytes))
		if err != nil {
			results <- Result{Source: p.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		req.Header.Set("Authorization", "Bearer "+s.Keys.PugRecon)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := s.Client.Do(req)
		if err != nil {
			results <- Result{Source: p.Name(), Error: fmt.Errorf("failed to execute request: %w", err)}
			return
		}
		defer resp.Body.Close()

		
		if resp.StatusCode == 401 {
			results <- Result{Source: p.Name(), Error: fmt.Errorf("invalid PugRecon API key")}
			return
		}

		if resp.StatusCode == 429 {
			results <- Result{Source: p.Name(), Error: fmt.Errorf("PugRecon rate limit exceeded")}
			return
		}

		if resp.StatusCode != http.StatusOK {
			
			var apiResp PugReconAPIResponse
			if json.NewDecoder(resp.Body).Decode(&apiResp) == nil && apiResp.Message != "" {
				results <- Result{Source: p.Name(), Error: fmt.Errorf("HTTP error %d: %s", resp.StatusCode, apiResp.Message)}
			} else {
				results <- Result{Source: p.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
			}
			return
		}

		
		var response PugReconAPIResponse
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			results <- Result{Source: p.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
			return
		}

		
		if response.Message != "" && len(response.Results) == 0 {
			results <- Result{Source: p.Name(), Error: fmt.Errorf("API error: %s", response.Message)}
			return
		}

		
		seen := make(map[string]bool)
		for _, result := range response.Results {
			hostname := strings.TrimSpace(strings.ToLower(result.Name))
			
			
			if hostname != "" && hostname != domain && 
			   strings.HasSuffix(hostname, "."+domain) && 
			   p.isValidHostname(hostname) && !seen[hostname] {
				seen[hostname] = true

				select {
				case results <- Result{Source: p.Name(), Value: hostname, Type: "subdomain"}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return results
}


func (p *PugRecon) isValidHostname(hostname string) bool {
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
