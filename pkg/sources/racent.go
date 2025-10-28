package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"github.com/samogod/samoscout/pkg/session"
	"strings"
)

type Racent struct{}

type RacentResponse struct {
	Data struct {
		List []struct {
			DNSNames []string `json:"dnsnames"`
		} `json:"list"`
	} `json:"data"`
}

func (r *Racent) Name() string {
	return "racent"
}

func (r *Racent) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		url := fmt.Sprintf("https://face.racent.com/tool/query_ctlog?keyword=%s", domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- Result{Source: r.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		req.Header.Set("Accept", "application/json")

		resp, err := s.Client.Do(req)
		if err != nil {
			results <- Result{Source: r.Name(), Error: fmt.Errorf("failed to execute request: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			results <- Result{Source: r.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
			return
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			results <- Result{Source: r.Name(), Error: fmt.Errorf("failed to read response body: %w", err)}
			return
		}

		bodyStr := string(body)
		if strings.Contains(bodyStr, "CTLog 查询超过限制") {
			results <- Result{Source: r.Name(), Error: fmt.Errorf("CTLog query limit exceeded")}
			return
		}

		var racentResp RacentResponse
		if err := json.Unmarshal(body, &racentResp); err != nil {
			results <- Result{Source: r.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
			return
		}

		seen := make(map[string]bool)

		for _, item := range racentResp.Data.List {
			for _, subdomain := range item.DNSNames {
				hostname := strings.TrimSpace(strings.ToLower(subdomain))

				if hostname != "" && hostname != domain &&
					strings.HasSuffix(hostname, "."+domain) &&
					r.isValidHostname(hostname) &&
					!seen[hostname] {
					seen[hostname] = true

					select {
					case results <- Result{Source: r.Name(), Value: hostname, Type: "subdomain"}:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	return results
}

// isValidHostname validates a hostname
func (r *Racent) isValidHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}

	// Check for leading or trailing dots
	if strings.HasPrefix(hostname, ".") || strings.HasSuffix(hostname, ".") {
		return false
	}

	if strings.Contains(hostname, "..") {
		return false
	}

	// Must contain at least one dot
	if !strings.Contains(hostname, ".") {
		return false
	}

	// Check for valid characters
	for _, char := range hostname {
		if !((char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') ||
			char == '-' || char == '.') {
			return false
		}
	}

	// Check for leading or trailing hyphens
	if strings.HasPrefix(hostname, "-") || strings.HasSuffix(hostname, "-") {
		return false
	}

	if strings.Contains(hostname, "--") {
		return false
	}

	return true
}
