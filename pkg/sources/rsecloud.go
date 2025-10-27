package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"samoscout/pkg/session"
	"strings"
)


type RSECloud struct{}


type RSECloudResponse struct {
	Count      int      `json:"count"`
	Data       []string `json:"data"`
	Page       int      `json:"page"`
	PageSize   int      `json:"pagesize"`
	TotalPages int      `json:"total_pages"`
}


func (r *RSECloud) Name() string {
	return "rsecloud"
}


func (r *RSECloud) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		if s.Keys.RSECloud == "" {
			results <- Result{Source: r.Name(), Error: fmt.Errorf("RSECloud API key not configured")}
			return
		}

		seen := make(map[string]bool)

		
		endpoints := []string{"active", "passive"}
		
		for _, endpoint := range endpoints {
			select {
			case <-ctx.Done():
				return
			default:
			}

			err := r.fetchSubdomains(ctx, endpoint, domain, s, results, seen)
			if err != nil {
				results <- Result{Source: r.Name(), Error: fmt.Errorf("%s endpoint failed: %w", endpoint, err)}
				continue
			}
		}
	}()

	return results
}


func (r *RSECloud) fetchSubdomains(ctx context.Context, endpoint, domain string, s *session.Session, results chan<- Result, seen map[string]bool) error {
	page := 1

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		
		url := fmt.Sprintf("https://api.rsecloud.com/api/v2/subdomains/%s/%s?page=%d", endpoint, domain, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("failed to create request for page %d: %w", page, err)
		}

		
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("X-API-Key", s.Keys.RSECloud)

		resp, err := s.Client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to execute request for page %d: %w", page, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == 401 {
			return fmt.Errorf("invalid RSECloud API key")
		}

		if resp.StatusCode == 429 {
			return fmt.Errorf("RSECloud rate limit exceeded")
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("HTTP error for page %d: %d", page, resp.StatusCode)
		}

		
		var rseCloudResponse RSECloudResponse
		if err := json.NewDecoder(resp.Body).Decode(&rseCloudResponse); err != nil {
			return fmt.Errorf("failed to decode JSON for page %d: %w", page, err)
		}

		
		for _, subdomain := range rseCloudResponse.Data {
			hostname := strings.TrimSpace(strings.ToLower(subdomain))
			
			
			if hostname != "" && hostname != domain && 
			   strings.HasSuffix(hostname, "."+domain) && 
			   r.isValidHostname(hostname) && !seen[hostname] {
				seen[hostname] = true

				select {
				case results <- Result{Source: r.Name(), Value: hostname, Type: "subdomain"}:
				case <-ctx.Done():
					return nil
				}
			}
		}

		
		if page >= rseCloudResponse.TotalPages || len(rseCloudResponse.Data) == 0 {
			break
		}
		page++
	}

	return nil
}


func (r *RSECloud) isValidHostname(hostname string) bool {
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
