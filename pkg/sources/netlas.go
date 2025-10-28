package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"github.com/samogod/samoscout/pkg/session"
	"strings"
)


type Netlas struct{}


type NetlasItem struct {
	Data struct {
		A           []string `json:"a,omitempty"`
		Txt         []string `json:"txt,omitempty"`
		LastUpdated string   `json:"last_updated,omitempty"`
		Timestamp   string   `json:"@timestamp,omitempty"`
		Ns          []string `json:"ns,omitempty"`
		Level       int      `json:"level,omitempty"`
		Zone        string   `json:"zone,omitempty"`
		Domain      string   `json:"domain,omitempty"`
		Cname       []string `json:"cname,omitempty"`
		Mx          []string `json:"mx,omitempty"`
	} `json:"data"`
}


type NetlasCountResponse struct {
	Count int `json:"count"`
}


func (n *Netlas) Name() string {
	return "netlas"
}


func (n *Netlas) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		if s.Keys.Netlas == "" {
			results <- Result{Source: n.Name(), Error: fmt.Errorf("Netlas API key not configured")}
			return
		}

		
		count, err := n.getDomainCount(ctx, domain, s)
		if err != nil {
			results <- Result{Source: n.Name(), Error: fmt.Errorf("failed to get domain count: %w", err)}
			return
		}

		if count == 0 {
			return 
		}

		
		domains, err := n.downloadDomains(ctx, domain, count, s)
		if err != nil {
			results <- Result{Source: n.Name(), Error: fmt.Errorf("failed to download domains: %w", err)}
			return
		}

		
		seen := make(map[string]bool)
		for _, item := range domains {
			hostname := strings.TrimSpace(strings.ToLower(item.Data.Domain))
			
			
			if hostname != "" && hostname != domain && 
			   strings.HasSuffix(hostname, "."+domain) && 
			   n.isValidHostname(hostname) && !seen[hostname] {
				seen[hostname] = true

				select {
				case results <- Result{Source: n.Name(), Value: hostname, Type: "subdomain"}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return results
}


func (n *Netlas) getDomainCount(ctx context.Context, domain string, s *session.Session) (int, error) {
	endpoint := "https://app.netlas.io/api/domains_count/"
	params := url.Values{}
	countQuery := fmt.Sprintf("domain:*.%s AND NOT domain:%s", domain, domain)
	params.Set("q", countQuery)
	countURL := endpoint + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, countURL, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create count request: %w", err)
	}

	
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.Keys.Netlas)

	resp, err := s.Client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to execute count request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return 0, fmt.Errorf("invalid Netlas API key")
	}

	if resp.StatusCode == 429 {
		return 0, fmt.Errorf("Netlas rate limit exceeded")
	}

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to read count response body: %w", err)
	}

	var countResp NetlasCountResponse
	if err := json.Unmarshal(body, &countResp); err != nil {
		return 0, fmt.Errorf("failed to decode count JSON: %w", err)
	}

	return countResp.Count, nil
}


func (n *Netlas) downloadDomains(ctx context.Context, domain string, count int, s *session.Session) ([]NetlasItem, error) {
	apiURL := "https://app.netlas.io/api/domains/download/"
	query := fmt.Sprintf("domain:*.%s AND NOT domain:%s", domain, domain)
	
	requestBody := map[string]interface{}{
		"q":           query,
		"fields":      []string{"*"},
		"source_type": "include",
		"size":        count,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create download request: %w", err)
	}

	
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.Keys.Netlas)

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute download request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("invalid Netlas API key")
	}

	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("Netlas rate limit exceeded")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read download response body: %w", err)
	}

	var domains []NetlasItem
	if err := json.Unmarshal(body, &domains); err != nil {
		return nil, fmt.Errorf("failed to decode domains JSON: %w", err)
	}

	return domains, nil
}


func (n *Netlas) isValidHostname(hostname string) bool {
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
