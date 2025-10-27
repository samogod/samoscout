package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"samoscout/pkg/session"
	"strings"
	"time"
)


type Cloudflare struct{}


type CloudflareAccountResponse struct {
	Result []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"result"`
	Success bool `json:"success"`
}


type CloudflareZoneResponse struct {
	Result []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"result"`
	Success bool `json:"success"`
}


type CloudflareCreateZoneRequest struct {
	Name      string `json:"name"`
	Account   struct {
		ID string `json:"id"`
	} `json:"account"`
	JumpStart bool   `json:"jump_start"`
	Type      string `json:"type"`
}


type CloudflareCreateZoneResponse struct {
	Result struct {
		ID string `json:"id"`
	} `json:"result"`
	Success bool `json:"success"`
}


type CloudflareDNSResponse struct {
	Result []struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Content string `json:"content"`
	} `json:"result"`
	ResultInfo struct {
		Page       int `json:"page"`
		PerPage    int `json:"per_page"`
		TotalPages int `json:"total_pages"`
		Count      int `json:"count"`
		TotalCount int `json:"total_count"`
	} `json:"result_info"`
	Success bool `json:"success"`
}


func (cf *Cloudflare) Name() string {
	return "cloudflare"
}

func (cf *Cloudflare) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		if s.Keys.Cloudflare == "" {
			results <- Result{Source: cf.Name(), Error: fmt.Errorf("Cloudflare API key not configured")}
			return
		}

		accountID, err := cf.getAccountID(ctx, s)
		if err != nil {
			results <- Result{Source: cf.Name(), Error: fmt.Errorf("failed to get account ID: %w", err)}
			return
		}

		zoneID, err := cf.getOrCreateZone(ctx, domain, accountID, s)
		if err != nil {
			results <- Result{Source: cf.Name(), Error: fmt.Errorf("failed to get/create zone: %w", err)}
			return
		}

		cf.listDNSRecords(ctx, zoneID, domain, s, results)
	}()

	return results
}

func (cf *Cloudflare) getAccountID(ctx context.Context, s *session.Session) (string, error) {
	url := "https://api.cloudflare.com/client/v4/accounts"
	
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+s.Keys.Cloudflare)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := s.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	var accountResp CloudflareAccountResponse
	if err := json.NewDecoder(resp.Body).Decode(&accountResp); err != nil {
		return "", fmt.Errorf("failed to decode JSON: %w", err)
	}

	if !accountResp.Success || len(accountResp.Result) == 0 {
		return "", fmt.Errorf("no accounts found or API error")
	}

	return accountResp.Result[0].ID, nil
}

func (cf *Cloudflare) getOrCreateZone(ctx context.Context, domain, accountID string, s *session.Session) (string, error) {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones?name=%s", domain)
	
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+s.Keys.Cloudflare)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := s.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 {
		return "", fmt.Errorf("domain is banned or not registered")
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	var zoneResp CloudflareZoneResponse
	if err := json.NewDecoder(resp.Body).Decode(&zoneResp); err != nil {
		return "", fmt.Errorf("failed to decode JSON: %w", err)
	}

	if zoneResp.Success && len(zoneResp.Result) > 0 {
		return zoneResp.Result[0].ID, nil
	}

	return cf.createZone(ctx, domain, accountID, s)
}

func (cf *Cloudflare) createZone(ctx context.Context, domain, accountID string, s *session.Session) (string, error) {
	url := "https://api.cloudflare.com/client/v4/zones"

	createReq := CloudflareCreateZoneRequest{
		Name:      domain,
		JumpStart: true,
		Type:      "full",
	}
	createReq.Account.ID = accountID

	jsonData, err := json.Marshal(createReq)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+s.Keys.Cloudflare)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := s.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP error creating zone: %d", resp.StatusCode)
	}

	var createResp CloudflareCreateZoneResponse
	if err := json.NewDecoder(resp.Body).Decode(&createResp); err != nil {
		return "", fmt.Errorf("failed to decode JSON: %w", err)
	}

	if !createResp.Success {
		return "", fmt.Errorf("zone creation failed")
	}

	return createResp.Result.ID, nil
}

func (cf *Cloudflare) listDNSRecords(ctx context.Context, zoneID, domain string, s *session.Session, results chan<- Result) {
	seen := make(map[string]bool)
	page := 1
	perPage := 100
	
	firstResults := cf.fetchDNSPage(ctx, zoneID, page, perPage, s)
	if firstResults == nil {
		return
	}
	if len(firstResults.Result) == 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
		
		firstResults = cf.fetchDNSPage(ctx, zoneID, page, perPage, s)
		if firstResults == nil || len(firstResults.Result) == 0 {
			return
		}
	}

	cf.processDNSResults(firstResults, domain, seen, results)

	totalPages := firstResults.ResultInfo.TotalPages
	
	for page = 2; page <= totalPages; page++ {
		select {
		case <-ctx.Done():
			return
		default:
		}

		pageResults := cf.fetchDNSPage(ctx, zoneID, page, perPage, s)
		if pageResults == nil {
			continue
		}

		cf.processDNSResults(pageResults, domain, seen, results)
	}
}

func (cf *Cloudflare) fetchDNSPage(ctx context.Context, zoneID string, page, perPage int, s *session.Session) *CloudflareDNSResponse {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?page=%d&per_page=%d", 
		zoneID, page, perPage)
	
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("Authorization", "Bearer "+s.Keys.Cloudflare)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var dnsResp CloudflareDNSResponse
	if err := json.NewDecoder(resp.Body).Decode(&dnsResp); err != nil {
		return nil
	}

	if !dnsResp.Success {
		return nil
	}

	return &dnsResp
}

func (cf *Cloudflare) processDNSResults(dnsResp *CloudflareDNSResponse, domain string, seen map[string]bool, results chan<- Result) {
	subdomainPattern := regexp.MustCompile(`[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.` + regexp.QuoteMeta(domain))
	
	for _, record := range dnsResp.Result {
		matches := subdomainPattern.FindAllString(record.Name, -1)
		for _, match := range matches {
			subdomain := strings.TrimSpace(strings.ToLower(match))
			
			if subdomain != "" && subdomain != domain && !seen[subdomain] {
				seen[subdomain] = true
				
				select {
				case results <- Result{Source: cf.Name(), Value: subdomain, Type: "subdomain"}:
				case <-time.After(100 * time.Millisecond):
					return
				}
			}
		}
		
		if record.Type == "CNAME" {
			matches = subdomainPattern.FindAllString(record.Content, -1)
			for _, match := range matches {
				subdomain := strings.TrimSpace(strings.ToLower(match))
				
				if subdomain != "" && subdomain != domain && !seen[subdomain] {
					seen[subdomain] = true
					
					select {
					case results <- Result{Source: cf.Name(), Value: subdomain, Type: "subdomain"}:
					case <-time.After(100 * time.Millisecond):
						return
					}
				}
			}
		}
	}
}
