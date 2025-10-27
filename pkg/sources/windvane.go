package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"samoscout/pkg/session"
	"strings"
)


type Windvane struct{}


type windvaneRequest struct {
	Domain      string      `json:"domain"`
	PageRequest pageRequest `json:"page_request"`
}


type pageRequest struct {
	Page  int `json:"page"`
	Count int `json:"count"`
}


type windvaneResponse struct {
	Code       int    `json:"code"`
	Msg        string `json:"msg"`
	Data       *data  `json:"data"`
	ServerTime string `json:"server_time"`
	Version    string `json:"version"`
}


type data struct {
	List         []subdomain    `json:"list"`
	PageResponse pageResponse   `json:"page_response"`
}


type subdomain struct {
	LastUpdatedAt string `json:"last_updated_at"`
	Domain        string `json:"domain"`
	UUID          string `json:"uuid"`
}


type pageResponse struct {
	Total     string `json:"total"`
	Count     string `json:"count"`
	TotalPage string `json:"total_page"`
}

const (
	windvaneBaseURL = "https://windvane.lichoin.com/trpc.backendhub.public.WindvaneService"
	windvanePageSize = 1000
	windvaneMaxResults = 50000
)


func (w *Windvane) Name() string {
	return "windvane"
}


func (w *Windvane) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		if s.Keys.Windvane == "" {
			results <- Result{Source: w.Name(), Error: fmt.Errorf("Windvane API key not configured")}
			return
		}


		seen := make(map[string]bool)
		page := 1
		totalFetched := 0
		maxPages := windvaneMaxResults / windvanePageSize

		for totalFetched < windvaneMaxResults {
			select {
			case <-ctx.Done():
				return
			default:
			}

			
			requestBody := windvaneRequest{
				Domain: domain,
				PageRequest: pageRequest{
					Page:  page,
					Count: windvanePageSize,
				},
			}

			jsonData, err := json.Marshal(requestBody)
			if err != nil {
				results <- Result{Source: w.Name(), Error: fmt.Errorf("failed to marshal request: %w", err)}
				return
			}

			url := windvaneBaseURL + "/ListSubDomain"

			req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(jsonData))
			if err != nil {
				results <- Result{Source: w.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
				return
			}

			
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Api-Key", s.Keys.Windvane)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

			resp, err := s.Client.Do(req)
			if err != nil {
				results <- Result{Source: w.Name(), Error: fmt.Errorf("API request failed: %w", err)}
				return
			}

			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				results <- Result{Source: w.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
				return
			}

			
			var windvaneResp windvaneResponse
			if err := json.NewDecoder(resp.Body).Decode(&windvaneResp); err != nil {
				resp.Body.Close()
				results <- Result{Source: w.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
				return
			}
			resp.Body.Close()

			
			if windvaneResp.Code != 0 {
				results <- Result{Source: w.Name(), Error: fmt.Errorf("API error %d: %s", windvaneResp.Code, windvaneResp.Msg)}
				return
			}

			
			if windvaneResp.Data == nil || len(windvaneResp.Data.List) == 0 {
				break
			}

			
			for _, sub := range windvaneResp.Data.List {
				hostname := strings.TrimSpace(strings.ToLower(sub.Domain))
				
				if hostname == "" {
					continue
				}

				
				if !seen[hostname] {
					seen[hostname] = true
					totalFetched++

					select {
					case results <- Result{Source: w.Name(), Value: hostname, Type: "subdomain"}:
					case <-ctx.Done():
						return
					}
				}
			}

			
			if len(windvaneResp.Data.List) < windvanePageSize {
				break
			}

			
			if page >= maxPages {
				break
			}

			page++
		}
	}()

	return results
}
