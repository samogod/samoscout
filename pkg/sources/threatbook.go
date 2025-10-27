package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"samoscout/pkg/session"
	"strconv"
	"strings"
)


type ThreatBook struct{}


type ThreatBookResponse struct {
	ResponseCode int64  `json:"response_code"`
	VerboseMsg   string `json:"verbose_msg"`
	Data         struct {
		Domain     string `json:"domain"`
		SubDomains struct {
			Total string   `json:"total"`
			Data  []string `json:"data"`
		} `json:"sub_domains"`
	} `json:"data"`
}


func (t *ThreatBook) Name() string {
	return "threatbook"
}


func (t *ThreatBook) Run(ctx context.Context, domain string, session *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		if session.Keys.ThreatBook == "" {
			results <- Result{Source: t.Name(), Error: fmt.Errorf("ThreatBook API key not configured")}
			return
		}

		seen := make(map[string]bool)
		url := fmt.Sprintf("https://api.threatbook.cn/v3/domain/sub_domains?apikey=%s&resource=%s", session.Keys.ThreatBook, domain)
		
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- Result{Source: t.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

		resp, err := session.Client.Do(req)
		if err != nil {
			results <- Result{Source: t.Name(), Error: fmt.Errorf("API request failed: %w", err)}
			return
		}
		defer resp.Body.Close()

		var response ThreatBookResponse
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			results <- Result{Source: t.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
			return
		}

		
		if response.ResponseCode != 0 {
			results <- Result{Source: t.Name(), Error: fmt.Errorf("API error code %d: %s", response.ResponseCode, response.VerboseMsg)}
			return
		}

		
		total, err := strconv.ParseInt(response.Data.SubDomains.Total, 10, 64)
		if err != nil {
			results <- Result{Source: t.Name(), Error: fmt.Errorf("failed to parse total count: %w", err)}
			return
		}

		
		if total > 0 {
			for _, subdomain := range response.Data.SubDomains.Data {
				hostname := strings.TrimSpace(strings.ToLower(subdomain))
				
				if hostname != "" && !seen[hostname] {
					seen[hostname] = true

					select {
					case results <- Result{Source: t.Name(), Value: hostname, Type: "subdomain"}:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	return results
}
