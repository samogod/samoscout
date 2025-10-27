package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"samoscout/pkg/session"
	"strings"
)

type ZoomEyeAPI struct{}

type ZoomEyeAPIResponse struct {
	Status int `json:"status"`
	Total  int `json:"total"`
	List   []struct {
		Name string   `json:"name"`
		IP   []string `json:"ip"`
	} `json:"list"`
}

func (z *ZoomEyeAPI) Name() string {
	return "zoomeye"
}

func (z *ZoomEyeAPI) Run(ctx context.Context, domain string, session *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		if session.Keys.ZoomEyeAPI == "" {
			results <- Result{Source: z.Name(), Error: fmt.Errorf("ZoomEyeAPI API key not configured")}
			return
		}

		apiKey := session.Keys.ZoomEyeAPI
		seen := make(map[string]bool)
		pages := 1

		for currentPage := 1; currentPage <= pages; currentPage++ {
			select {
			case <-ctx.Done():
				return
			default:
			}

			apiURL := fmt.Sprintf("https://api.zoomeye.org/domain/search?q=%s&type=1&s=1000&page=%d", domain, currentPage)

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
			if err != nil {
				results <- Result{Source: z.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
				return
			}

			req.Header.Set("API-KEY", apiKey)
			req.Header.Set("Accept", "application/json")
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

			resp, err := session.Client.Do(req)
			if err != nil {
				results <- Result{Source: z.Name(), Error: fmt.Errorf("API request failed: %w", err)}
				return
			}

			if resp.StatusCode == 401 {
				resp.Body.Close()
				results <- Result{Source: z.Name(), Error: fmt.Errorf("invalid ZoomEyeAPI API key")}
				return
			}

			if resp.StatusCode == 403 {
				resp.Body.Close()
				results <- Result{Source: z.Name(), Error: fmt.Errorf("ZoomEyeAPI access forbidden - check API key permissions")}
				return
			}

			if resp.StatusCode == 429 {
				resp.Body.Close()
				results <- Result{Source: z.Name(), Error: fmt.Errorf("ZoomEyeAPI rate limit exceeded")}
				return
			}

			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				results <- Result{Source: z.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
				return
			}

			var response ZoomEyeAPIResponse
			if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
				resp.Body.Close()
				results <- Result{Source: z.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
				return
			}
			resp.Body.Close()

			if currentPage == 1 {
				pages = int(response.Total/1000) + 1
			}

			for _, item := range response.List {
				hostname := strings.TrimSpace(strings.ToLower(item.Name))

				if hostname != "" && !seen[hostname] {
					seen[hostname] = true

					select {
					case results <- Result{Source: z.Name(), Value: hostname, Type: "subdomain"}:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	return results
}
