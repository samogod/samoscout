package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"samoscout/pkg/session"
	"strings"
)


type JSMon struct{}


type subdomainsResponse struct {
	Subdomains []string `json:"subdomains"`
	Status     string   `json:"status"`
	Message    string   `json:"message"`
}

const (
	jsmonBaseURL = "https://api.jsmon.sh"
)


func (j *JSMon) Name() string {
	return "jsmon"
}


func (j *JSMon) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		if s.Keys.JSMon == "" {
			results <- Result{Source: j.Name(), Error: fmt.Errorf("JSMon API key not configured")}
			return
		}

		fmt.Printf("[DEBUG] JSMon: Starting scan for domain: %s\n", domain)

		
		apiKeyParts := strings.Split(s.Keys.JSMon, ":")
		if len(apiKeyParts) != 2 {
			fmt.Printf("[DEBUG] JSMon: Invalid API key format, expected authToken:workspaceId\n")
			results <- Result{Source: j.Name(), Error: fmt.Errorf("JSMon API key format should be authToken:workspaceId")}
			return
		}

		authToken := apiKeyParts[0]
		wkspId := apiKeyParts[1]

		fmt.Printf("[DEBUG] JSMon: API key configured - AuthToken: %s..., WorkspaceId: %s\n", authToken[:8], wkspId)

		
		samoscoutScanURL := fmt.Sprintf("%s/api/v2/subfinderScan2?wkspId=%s", jsmonBaseURL, wkspId)
		requestBody := fmt.Sprintf(`{"domain":"%s"}`, domain)

		fmt.Printf("[DEBUG] JSMon: Making POST request to: %s\n", samoscoutScanURL)
		fmt.Printf("[DEBUG] JSMon: Request body: %s\n", requestBody)
		fmt.Printf("[DEBUG] JSMon: Using X-Jsmon-Key header with token: %s...\n", authToken[:8])

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, samoscoutScanURL, bytes.NewReader([]byte(requestBody)))
		if err != nil {
			fmt.Printf("[DEBUG] JSMon: Failed to create HTTP request: %v\n", err)
			results <- Result{Source: j.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		
		req.Header.Set("X-Jsmon-Key", authToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

		fmt.Printf("[DEBUG] JSMon: Request headers set - X-Jsmon-Key, Content-Type, User-Agent\n")

		resp, err := s.Client.Do(req)
		if err != nil {
			fmt.Printf("[DEBUG] JSMon: Request failed: %v\n", err)
			results <- Result{Source: j.Name(), Error: fmt.Errorf("API request failed: %w", err)}
			return
		}

		fmt.Printf("[DEBUG] JSMon: Response status: %d\n", resp.StatusCode)

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			fmt.Printf("[DEBUG] JSMon: Non-200 status code received: %d\n", resp.StatusCode)
			fmt.Printf("[DEBUG] JSMon: API error response body: %s\n", string(body))
			results <- Result{Source: j.Name(), Error: fmt.Errorf("samoscoutScan API returned status %d: %s", resp.StatusCode, string(body))}
			return
		}

		fmt.Printf("[DEBUG] JSMon: Received 200 OK, decoding JSON response...\n")

		
		var response subdomainsResponse
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			resp.Body.Close()
			fmt.Printf("[DEBUG] JSMon: JSON decode failed: %v\n", err)
			results <- Result{Source: j.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
			return
		}
		resp.Body.Close()

		fmt.Printf("[DEBUG] JSMon: JSON decode successful\n")
		fmt.Printf("[DEBUG] JSMon: API response - Status: '%s', Message: '%s', Subdomains count: %d\n", response.Status, response.Message, len(response.Subdomains))

		
		if response.Status != "" && response.Status != "success" && response.Status != "ok" {
			fmt.Printf("[DEBUG] JSMon: API returned error status: '%s' with message: '%s'\n", response.Status, response.Message)
			results <- Result{Source: j.Name(), Error: fmt.Errorf("API status error: %s - %s", response.Status, response.Message)}
			return
		}

		fmt.Printf("[DEBUG] JSMon: API status check passed, processing subdomains...\n")

		
		seen := make(map[string]bool)
		totalFetched := 0

		if len(response.Subdomains) == 0 {
			fmt.Printf("[DEBUG] JSMon: No subdomains found in response\n")
		}

		for i, subdomain := range response.Subdomains {
			hostname := strings.TrimSpace(strings.ToLower(subdomain))
			
			fmt.Printf("[DEBUG] JSMon: Processing result %d/%d - Subdomain: '%s'\n", i+1, len(response.Subdomains), hostname)

			if hostname == "" {
				fmt.Printf("[DEBUG] JSMon: Empty hostname, skipping\n")
				continue
			}

			
			if !seen[hostname] {
				seen[hostname] = true
				totalFetched++
				fmt.Printf("[DEBUG] JSMon: ✅ Found valid subdomain: '%s'\n", hostname)

				select {
				case results <- Result{Source: j.Name(), Value: hostname, Type: "subdomain"}:
				case <-ctx.Done():
					fmt.Printf("[DEBUG] JSMon: Context cancelled, stopping processing\n")
					return
				}
			} else {
				fmt.Printf("[DEBUG] JSMon: ⚠️ Duplicate subdomain skipped: '%s'\n", hostname)
			}
		}

		fmt.Printf("[DEBUG] JSMon: 🎉 Scan completed successfully - Total unique subdomains fetched: %d\n", totalFetched)
	}()

	return results
}
