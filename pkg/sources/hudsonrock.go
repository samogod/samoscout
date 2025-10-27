package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"samoscout/pkg/session"
	"strings"
)


type HudsonRock struct{}


type HudsonRockResponse struct {
	Data struct {
		EmployeesUrls []struct {
			URL string `json:"url"`
		} `json:"employees_urls"`
		ClientsUrls []struct {
			URL string `json:"url"`
		} `json:"clients_urls"`
	} `json:"data"`
}


func (h *HudsonRock) Name() string {
	return "hudsonrock"
}


func (h *HudsonRock) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		apiURL := fmt.Sprintf("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain?domain=%s", domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
		if err != nil {
			results <- Result{Source: h.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		req.Header.Set("Accept", "application/json")

		resp, err := s.Client.Do(req)
		if err != nil {
			results <- Result{Source: h.Name(), Error: fmt.Errorf("failed to execute request: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == 429 {
			results <- Result{Source: h.Name(), Error: fmt.Errorf("HudsonRock rate limit exceeded")}
			return
		}

		if resp.StatusCode != http.StatusOK {
			results <- Result{Source: h.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
			return
		}

		
		var hudsonRockResp HudsonRockResponse
		if err := json.NewDecoder(resp.Body).Decode(&hudsonRockResp); err != nil {
			results <- Result{Source: h.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
			return
		}

		
		allUrls := append(hudsonRockResp.Data.EmployeesUrls, hudsonRockResp.Data.ClientsUrls...)
		seen := make(map[string]bool)
		
		
		for _, record := range allUrls {
			if record.URL == "" {
				continue
			}
			
			subdomains := h.extractSubdomains(record.URL, domain)
			for _, subdomain := range subdomains {
				if subdomain != "" && !seen[subdomain] {
					seen[subdomain] = true
					
					select {
					case results <- Result{Source: h.Name(), Value: subdomain, Type: "subdomain"}:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	return results
}


func (h *HudsonRock) extractSubdomains(rawURL, domain string) []string {
	var subdomains []string
	
	
	if parsedURL, err := url.Parse(rawURL); err == nil && parsedURL.Host != "" {
		hostname := strings.ToLower(strings.TrimSpace(parsedURL.Host))
		
		
		if colonIndex := strings.LastIndex(hostname, ":"); colonIndex > 0 {
			if portPart := hostname[colonIndex+1:]; h.isNumeric(portPart) {
				hostname = hostname[:colonIndex]
			}
		}
		
		
		if hostname != "" && hostname != domain && 
		   strings.HasSuffix(hostname, "."+domain) && 
		   h.isValidHostname(hostname) {
			subdomains = append(subdomains, hostname)
		}
	}
	
	
	words := strings.Fields(rawURL)
	for _, word := range words {
		
		if strings.Contains(word, ".") && strings.Contains(word, domain) {
			
			cleanWord := strings.Trim(word, ".,;:!?()[]{}\"'/\\")
			cleanWord = strings.ToLower(cleanWord)
			
			
			if strings.HasPrefix(cleanWord, "http://") {
				cleanWord = cleanWord[7:]
			} else if strings.HasPrefix(cleanWord, "https://") {
				cleanWord = cleanWord[8:]
			}
			
			
			if slashIndex := strings.Index(cleanWord, "/"); slashIndex > 0 {
				cleanWord = cleanWord[:slashIndex]
			}
			
			
			if cleanWord != "" && cleanWord != domain && 
			   strings.HasSuffix(cleanWord, "."+domain) && 
			   h.isValidHostname(cleanWord) {
				subdomains = append(subdomains, cleanWord)
			}
		}
	}
	
	return subdomains
}


func (h *HudsonRock) isNumeric(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}


func (h *HudsonRock) isValidHostname(hostname string) bool {
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

	
	if strings.Contains(hostname, "•") || strings.Contains(hostname, "*") {
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
