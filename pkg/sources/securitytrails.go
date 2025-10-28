package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"github.com/samogod/samoscout/pkg/session"
	"strings"
)


type SecurityTrails struct{}


type SecurityTrailsResponse struct {
	Meta struct {
		ScrollID string `json:"scroll_id"`
	} `json:"meta"`
	Records []struct {
		Hostname string `json:"hostname"`
	} `json:"records"`
	Subdomains []string `json:"subdomains"`
}


func (st *SecurityTrails) Name() string {
	return "securitytrails"
}


func (st *SecurityTrails) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		if s.Keys.SecurityTrails == "" {
			results <- Result{Source: st.Name(), Error: fmt.Errorf("SecurityTrails API key not configured")}
			return
		}

		seen := make(map[string]bool)
		var scrollID string
		headers := map[string]string{"Content-Type": "application/json", "APIKEY": s.Keys.SecurityTrails}

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			var resp *http.Response
			var err error

			
			if scrollID == "" {
				
				requestBody := fmt.Appendf(nil, `{"query":"apex_domain='%s'"}`, domain)
				url := "https://api.securitytrails.com/v1/domains/list?include_ips=false&scroll=true"
				resp, err = st.makePostRequestRaw(ctx, url, requestBody, headers, s)
			} else {
				
				url := fmt.Sprintf("https://api.securitytrails.com/v1/scroll/%s", scrollID)
				resp, err = st.makeGetRequestRaw(ctx, url, headers, s)
			}

			
			if err != nil && st.safeStatusCode(resp) == 403 {
				fallbackURL := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", domain)
				resp, err = st.makeGetRequestRaw(ctx, fallbackURL, headers, s)
			}

			if err != nil {
				results <- Result{Source: st.Name(), Error: fmt.Errorf("API request failed: %w", err)}
				return
			}

			
			bodyBytes, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			
			if readErr != nil {
				results <- Result{Source: st.Name(), Error: fmt.Errorf("failed to read response body: %w", readErr)}
				return
			}
			
			var securityTrailsResponse SecurityTrailsResponse
			if err := json.Unmarshal(bodyBytes, &securityTrailsResponse); err != nil {
				results <- Result{Source: st.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
				return
			}

			
			for _, record := range securityTrailsResponse.Records {
				hostname := strings.TrimSpace(strings.ToLower(record.Hostname))
				
				if hostname != "" && !seen[hostname] {
					seen[hostname] = true

					select {
					case results <- Result{Source: st.Name(), Value: hostname, Type: "subdomain"}:
					case <-ctx.Done():
						return
					}
				}
			}

			
			for _, subdomain := range securityTrailsResponse.Subdomains {
				var fullDomain string
				
				
				if strings.HasSuffix(subdomain, ".") {
					fullDomain = subdomain + domain
				} else {
					fullDomain = subdomain + "." + domain
				}

				hostname := strings.TrimSpace(strings.ToLower(fullDomain))
				
				if hostname != "" && !seen[hostname] {
					seen[hostname] = true

					select {
					case results <- Result{Source: st.Name(), Value: hostname, Type: "subdomain"}:
					case <-ctx.Done():
						return
					}
				}
			}

			
			scrollID = securityTrailsResponse.Meta.ScrollID

			
			if scrollID == "" {
				break
			}
		}
	}()

	return results
}


func (st *SecurityTrails) safeStatusCode(resp *http.Response) int {
	if resp == nil {
		return 0
	}
	return resp.StatusCode
}


func (st *SecurityTrails) makePostRequestRaw(ctx context.Context, url string, body []byte, headers map[string]string, s *session.Session) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create POST request: %w", err)
	}

	
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return resp, err 
	}

	return resp, nil
}


func (st *SecurityTrails) makeGetRequestRaw(ctx context.Context, url string, headers map[string]string, s *session.Session) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create GET request: %w", err)
	}

	
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return resp, err 
	}

	return resp, nil
}


func (st *SecurityTrails) makePostRequest(ctx context.Context, url, body string, s *session.Session) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader([]byte(body)))
	if err != nil {
		return nil, fmt.Errorf("failed to create POST request: %w", err)
	}

	
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("APIKEY", s.Keys.SecurityTrails)

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute POST request: %w", err)
	}

	if resp.StatusCode == 401 {
		resp.Body.Close()
		return nil, fmt.Errorf("invalid SecurityTrails API key")
	}

	if resp.StatusCode == 429 {
		resp.Body.Close()
		return nil, fmt.Errorf("SecurityTrails rate limit exceeded")
	}

	return resp, nil
}


func (st *SecurityTrails) makeGetRequest(ctx context.Context, url string, s *session.Session) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create GET request: %w", err)
	}

	
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("APIKEY", s.Keys.SecurityTrails)

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute GET request: %w", err)
	}

	if resp.StatusCode == 401 {
		resp.Body.Close()
		return nil, fmt.Errorf("invalid SecurityTrails API key")
	}

	if resp.StatusCode == 429 {
		resp.Body.Close()
		return nil, fmt.Errorf("SecurityTrails rate limit exceeded")
	}

	return resp, nil
}


func (st *SecurityTrails) isValidHostname(hostname string) bool {
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
