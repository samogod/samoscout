package sources

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"samoscout/pkg/session"
	"strings"
)


type Fofa struct{}


type FofaResponse struct {
	Error   bool     `json:"error"`
	ErrMsg  string   `json:"errmsg"`
	Size    int      `json:"size"`
	Results []string `json:"results"`
}


func (f *Fofa) Name() string {
	return "fofa"
}


func (f *Fofa) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		if s.Keys.Fofa == "" {
			results <- Result{Source: f.Name(), Error: fmt.Errorf("Fofa API key not configured")}
			return
		}

		
		apiKeyParts := strings.Split(s.Keys.Fofa, ":")
		if len(apiKeyParts) != 2 {
			results <- Result{Source: f.Name(), Error: fmt.Errorf("Fofa API key must be in format 'username:secret'")}
			return
		}

		username := apiKeyParts[0]
		secret := apiKeyParts[1]

		
		query := fmt.Sprintf("domain=\"%s\"", domain)
		qbase64 := base64.StdEncoding.EncodeToString([]byte(query))

		
		url := fmt.Sprintf("https://fofa.info/api/v1/search/all?full=true&fields=host&page=1&size=10000&email=%s&key=%s&qbase64=%s", 
			username, secret, qbase64)
		
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- Result{Source: f.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		req.Header.Set("Accept", "application/json")

		resp, err := s.Client.Do(req)
		if err != nil {
			results <- Result{Source: f.Name(), Error: fmt.Errorf("failed to execute request: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == 401 {
			results <- Result{Source: f.Name(), Error: fmt.Errorf("invalid Fofa API credentials")}
			return
		}

		if resp.StatusCode == 429 {
			results <- Result{Source: f.Name(), Error: fmt.Errorf("Fofa rate limit exceeded")}
			return
		}

		if resp.StatusCode != http.StatusOK {
			results <- Result{Source: f.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
			return
		}

		
		var fofaResp FofaResponse
		if err := json.NewDecoder(resp.Body).Decode(&fofaResp); err != nil {
			results <- Result{Source: f.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
			return
		}

		
		if fofaResp.Error {
			results <- Result{Source: f.Name(), Error: fmt.Errorf("Fofa API error: %s", fofaResp.ErrMsg)}
			return
		}

		
		seen := make(map[string]bool)
		if fofaResp.Size > 0 {
			for _, subdomain := range fofaResp.Results {
				hostname := f.cleanHostname(subdomain, domain)
				if hostname != "" && !seen[hostname] {
					seen[hostname] = true

					select {
					case results <- Result{Source: f.Name(), Value: hostname, Type: "subdomain"}:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	return results
}


func (f *Fofa) cleanHostname(raw, domain string) string {
	hostname := strings.TrimSpace(strings.ToLower(raw))
	
	
	if strings.HasPrefix(hostname, "http://") {
		hostname = hostname[7:]
	} else if strings.HasPrefix(hostname, "https://") {
		hostname = hostname[8:]
	}
	
	
	re := regexp.MustCompile(`:\d+$`)
	if re.MatchString(hostname) {
		hostname = re.ReplaceAllString(hostname, "")
	}
	
	
	if slashIndex := strings.Index(hostname, "/"); slashIndex > 0 {
		hostname = hostname[:slashIndex]
	}
	
	
	if questionIndex := strings.Index(hostname, "?"); questionIndex > 0 {
		hostname = hostname[:questionIndex]
	}
	
	
	hostname = strings.Trim(hostname, ".,;:!?()[]{}\"'/\\")
	
	
	if hostname != "" && hostname != domain && 
	   strings.HasSuffix(hostname, "."+domain) && 
	   f.isValidHostname(hostname) {
		return hostname
	}
	
	return ""
}


func (f *Fofa) isValidHostname(hostname string) bool {
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

	return true
}
