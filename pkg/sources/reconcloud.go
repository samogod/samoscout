package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"samoscout/pkg/session"
	"strings"
)


type ReconCloud struct{}


type ReconCloudResponse struct {
	MsgType         string              `json:"msg_type"`
	RequestID       string              `json:"request_id"`
	OnCache         bool                `json:"on_cache"`
	Step            string              `json:"step"`
	CloudAssetsList []CloudAssetsList   `json:"cloud_assets_list"`
}


type CloudAssetsList struct {
	Key           string `json:"key"`
	Domain        string `json:"domain"`
	CloudProvider string `json:"cloud_provider"`
}


func (r *ReconCloud) Name() string {
	return "reconcloud"
}


func (r *ReconCloud) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		url := fmt.Sprintf("https://recon.cloud/api/search?domain=%s", domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- Result{Source: r.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		req.Header.Set("Accept", "application/json")

		resp, err := s.Client.Do(req)
		if err != nil {
			results <- Result{Source: r.Name(), Error: fmt.Errorf("failed to execute request: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == 429 {
			results <- Result{Source: r.Name(), Error: fmt.Errorf("ReconCloud rate limit exceeded")}
			return
		}

		if resp.StatusCode != http.StatusOK {
			results <- Result{Source: r.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
			return
		}

		
		var response ReconCloudResponse
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			results <- Result{Source: r.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
			return
		}

		
		seen := make(map[string]bool)
		if len(response.CloudAssetsList) > 0 {
			for _, cloudAsset := range response.CloudAssetsList {
				hostname := strings.TrimSpace(strings.ToLower(cloudAsset.Domain))
				
				
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
	}()

	return results
}


func (r *ReconCloud) isValidHostname(hostname string) bool {
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
