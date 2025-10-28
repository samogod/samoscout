package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"github.com/samogod/samoscout/pkg/session"
	"strings"
	"sync/atomic"
	"time"
)


type URLScan struct{}

const (
	urlscanBaseURL    = "https://urlscan.io/api/v1/"
	urlscanPageSize   = 100
	urlscanMaxResults = 10000
	maxPageRetries    = 3
	backoffBase       = 2 * time.Second
)


type searchResponse struct {
	Total   int `json:"total"`
	Results []struct {
		Task struct {
			URL string `json:"url"`
		} `json:"task"`
		Page struct {
			Domain string `json:"domain"`
		} `json:"page"`
	} `json:"results"`
}


func (u *URLScan) Name() string {
	return "urlscan"
}


func (u *URLScan) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		if s.Keys.URLScan == "" {
			results <- Result{Source: u.Name(), Error: fmt.Errorf("URLScan API key not configured")}
			return
		}


		seen := make(map[string]bool)
		var errors, resultCount atomic.Int32
		totalFetched := 0

		headers := map[string]string{
			"accept":  "application/json",
			"API-Key": s.Keys.URLScan,
		}

		page := 0
		for totalFetched < urlscanMaxResults {
			select {
			case <-ctx.Done():
				return
			default:
			}

			
			q := "domain:" + domain
			apiURL := urlscanBaseURL + "search/?" +
				"q=" + url.QueryEscape(q) +
				"&size=" + url.QueryEscape(fmt.Sprintf("%d", urlscanPageSize))
			
			
			if page > 0 {
				offset := page * urlscanPageSize
				apiURL += "&search_after=" + url.QueryEscape(fmt.Sprintf("%d", offset))
			}


			var resp *http.Response
			var err error
			backoff := backoffBase

			
			for attempt := 0; attempt <= maxPageRetries; attempt++ {
				req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
				if reqErr != nil {
					results <- Result{Source: u.Name(), Error: fmt.Errorf("failed to create request: %w", reqErr)}
					return
				}

				
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
				for key, value := range headers {
					req.Header.Set(key, value)
				}

				resp, err = s.Client.Do(req)
				if err != nil {
					results <- Result{Source: u.Name(), Error: fmt.Errorf("API request failed: %w", err)}
					errors.Add(1)
					break
				}

				if resp.StatusCode == http.StatusOK {
					break
				}

				resp.Body.Close()

				
				if resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode >= 500 && resp.StatusCode < 600) {
					select {
					case <-time.After(backoff):
						backoff *= 2
						continue
					case <-ctx.Done():
						return
					}
				}

				
				err = fmt.Errorf("URLScan API returned status %d", resp.StatusCode)
				results <- Result{Source: u.Name(), Error: err}
				errors.Add(1)
				break
			}

			if err != nil {
				break
			}

			
			var sr searchResponse
			if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
				resp.Body.Close()
				results <- Result{Source: u.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
				errors.Add(1)
				break
			}
			resp.Body.Close()

			
			if len(sr.Results) == 0 {
				break
			}

			
			for _, r := range sr.Results {
				if totalFetched >= urlscanMaxResults {
					break
				}

				host := strings.ToLower(strings.TrimSpace(r.Page.Domain))
				
				
				if host == "" && r.Task.URL != "" {
					if parsed, parseErr := url.Parse(r.Task.URL); parseErr == nil && parsed != nil {
						host = strings.ToLower(parsed.Hostname())
					}
				}

				if host == "" {
					continue
				}

				
				host = strings.TrimPrefix(host, "www.")

				
				if !strings.HasSuffix(host, "."+domain) && host != domain {
					continue
				}

				
				if !seen[host] {
					seen[host] = true
					resultCount.Add(1)
					totalFetched++

					select {
					case results <- Result{Source: u.Name(), Value: host, Type: "subdomain"}:
					case <-ctx.Done():
						return
					}
				}
			}

			
			if len(sr.Results) < urlscanPageSize {
				break
			}

			page++
		}
	}()

	return results
}
