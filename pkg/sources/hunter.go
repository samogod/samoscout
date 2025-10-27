package sources

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"samoscout/pkg/session"
	"strings"
)


type Hunter struct{}


type HunterResponse struct {
	Code    int         `json:"code"`
	Data    HunterData  `json:"data"`
	Message string      `json:"message"`
}

type HunterData struct {
	InfoArr []HunterInfo `json:"arr"`
	Total   int          `json:"total"`
}

type HunterInfo struct {
	URL      string `json:"url"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Domain   string `json:"domain"`
	Protocol string `json:"protocol"`
}


func (h *Hunter) Name() string {
	return "hunter"
}


func (h *Hunter) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		if s.Keys.Hunter == "" {
			results <- Result{Source: h.Name(), Error: fmt.Errorf("Hunter API key not configured")}
			return
		}

		
		var pages = 1
		seen := make(map[string]bool)

		for currentPage := 1; currentPage <= pages; currentPage++ {
			select {
			case <-ctx.Done():
				return
			default:
			}

			
			query := fmt.Sprintf("domain=\"%s\"", domain)
			qbase64 := base64.URLEncoding.EncodeToString([]byte(query))

			
			url := fmt.Sprintf("https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=%d&page_size=100&is_web=3", 
				s.Keys.Hunter, qbase64, currentPage)

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				results <- Result{Source: h.Name(), Error: fmt.Errorf("failed to create request for page %d: %w", currentPage, err)}
				return
			}

			
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
			req.Header.Set("Accept", "application/json")

			resp, err := s.Client.Do(req)
			if err != nil {
				results <- Result{Source: h.Name(), Error: fmt.Errorf("failed to execute request for page %d: %w", currentPage, err)}
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == 401 {
				results <- Result{Source: h.Name(), Error: fmt.Errorf("invalid Hunter API key")}
				return
			}

			if resp.StatusCode == 429 {
				results <- Result{Source: h.Name(), Error: fmt.Errorf("Hunter rate limit exceeded")}
				return
			}

			if resp.StatusCode != http.StatusOK {
				results <- Result{Source: h.Name(), Error: fmt.Errorf("HTTP error for page %d: %d", currentPage, resp.StatusCode)}
				return
			}

			
			var hunterResp HunterResponse
			if err := json.NewDecoder(resp.Body).Decode(&hunterResp); err != nil {
				results <- Result{Source: h.Name(), Error: fmt.Errorf("failed to decode JSON for page %d: %w", currentPage, err)}
				return
			}

			
			if hunterResp.Code == 401 || hunterResp.Code == 400 {
				results <- Result{Source: h.Name(), Error: fmt.Errorf("Hunter API error: %s (code: %d)", hunterResp.Message, hunterResp.Code)}
				return
			}

			
			if hunterResp.Data.Total > 0 {
				for _, hunterInfo := range hunterResp.Data.InfoArr {
					hostname := strings.TrimSpace(strings.ToLower(hunterInfo.Domain))
					
					
					if hostname != "" && hostname != domain && 
					   strings.HasSuffix(hostname, "."+domain) && 
					   h.isValidHostname(hostname) && !seen[hostname] {
						seen[hostname] = true

						select {
						case results <- Result{Source: h.Name(), Value: hostname, Type: "subdomain"}:
						case <-ctx.Done():
							return
						}
					}
				}

				
				if currentPage == 1 {
					pages = hunterResp.Data.Total/100 + 1
					if pages > 10 {
						pages = 10
					}
				}
			}
		}
	}()

	return results
}


func (h *Hunter) isValidHostname(hostname string) bool {
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
