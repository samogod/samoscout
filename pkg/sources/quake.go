package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"samoscout/pkg/session"
	"strings"
)


type Quake struct{}


type QuakeResults struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    []struct {
		Service struct {
			HTTP struct {
				Host string `json:"host"`
			} `json:"http"`
		} `json:"service"`
	} `json:"data"`
	Meta struct {
		Pagination struct {
			Total int `json:"total"`
		} `json:"pagination"`
	} `json:"meta"`
}


func (q *Quake) Name() string {
	return "quake"
}


func (q *Quake) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		if s.Keys.Quake == "" {
			results <- Result{Source: q.Name(), Error: fmt.Errorf("Quake API key not configured")}
			return
		}

		
		var pageSize = 500
		var start = 0
		var totalResults = -1
		seen := make(map[string]bool)

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			
			requestBody := fmt.Sprintf(`{"query":"domain: %s", "include":["service.http.host"], "latest": true, "size":%d, "start":%d}`, 
				domain, pageSize, start)

			
			apiURL := "https://quake.360.net/api/v3/search/quake_service"
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader([]byte(requestBody)))
			if err != nil {
				results <- Result{Source: q.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
				return
			}

			
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-QuakeToken", s.Keys.Quake)

			resp, err := s.Client.Do(req)
			if err != nil {
				results <- Result{Source: q.Name(), Error: fmt.Errorf("failed to execute request: %w", err)}
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == 401 {
				results <- Result{Source: q.Name(), Error: fmt.Errorf("invalid Quake API key")}
				return
			}

			if resp.StatusCode == 429 {
				results <- Result{Source: q.Name(), Error: fmt.Errorf("Quake rate limit exceeded")}
				return
			}

			if resp.StatusCode != http.StatusOK {
				results <- Result{Source: q.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
				return
			}

			
			var response QuakeResults
			if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
				results <- Result{Source: q.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
				return
			}

			
			if response.Code != 0 {
				results <- Result{Source: q.Name(), Error: fmt.Errorf("Quake API error: %s (code: %d)", response.Message, response.Code)}
				return
			}

			
			if totalResults == -1 {
				totalResults = response.Meta.Pagination.Total
			}

			
			for _, quakeDomain := range response.Data {
				hostname := strings.TrimSpace(strings.ToLower(quakeDomain.Service.HTTP.Host))
				
				
				if strings.Contains(hostname, "暂无权限") {
					continue
				}
				
				
				if hostname != "" && hostname != domain && 
				   strings.HasSuffix(hostname, "."+domain) && 
				   q.isValidHostname(hostname) && !seen[hostname] {
					seen[hostname] = true

					select {
					case results <- Result{Source: q.Name(), Value: hostname, Type: "subdomain"}:
					case <-ctx.Done():
						return
					}
				}
			}

			
			if len(response.Data) == 0 || start+pageSize >= totalResults {
				break
			}

			start += pageSize
		}
	}()

	return results
}


func (q *Quake) isValidHostname(hostname string) bool {
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
