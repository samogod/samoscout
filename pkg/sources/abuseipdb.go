package sources

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"github.com/samogod/samoscout/pkg/session"
	"strings"
)

// AbuseIPDB struct for the AbuseIPDB source
type AbuseIPDB struct{}

// Regex pattern to match <li> tags
var liTagPattern = regexp.MustCompile(`<li>\w[^<]*</li>`)

// Name returns the name of the source
func (a *AbuseIPDB) Name() string {
	return "abuseipdb"
}

// Run performs subdomain enumeration using AbuseIPDB WHOIS service
func (a *AbuseIPDB) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		// Construct the URL
		url := fmt.Sprintf("https://www.abuseipdb.com/whois/%s", domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- Result{Source: a.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
			return
		}

		// Set headers - AbuseIPDB requires Firefox-like user agent to avoid 403
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:110.0) Gecko/20100101 Firefox/110.0")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		req.Header.Set("Referer", "https://www.abuseipdb.com/")

		// Set session cookie to bypass basic anti-bot protection
		req.Header.Set("Cookie", "abuseipdb_session=; XSRF-TOKEN=")

		resp, err := s.Client.Do(req)
		if err != nil {
			results <- Result{Source: a.Name(), Error: fmt.Errorf("failed to execute request: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			results <- Result{Source: a.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
			return
		}

		// Read the response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			results <- Result{Source: a.Name(), Error: fmt.Errorf("failed to read response body: %w", err)}
			return
		}

		html := string(body)

		// Extract subdomains from <li> tags
		matches := liTagPattern.FindAllString(html, -1)
		seen := make(map[string]bool)

		for _, match := range matches {
			// Remove <li> and </li> tags
			subdomain := strings.TrimSpace(match)
			subdomain = strings.TrimPrefix(subdomain, "<li>")
			subdomain = strings.TrimSuffix(subdomain, "</li>")
			subdomain = strings.TrimSpace(subdomain)

			// Skip if empty
			if subdomain == "" {
				continue
			}

			// Construct full domain
			fullDomain := subdomain + "." + domain
			hostname := strings.TrimSpace(strings.ToLower(fullDomain))

			// Validate and send
			if hostname != "" && hostname != domain &&
				strings.HasSuffix(hostname, "."+domain) &&
				a.isValidHostname(hostname) &&
				!seen[hostname] {
				seen[hostname] = true

				select {
				case results <- Result{Source: a.Name(), Value: hostname, Type: "subdomain"}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return results
}

// isValidHostname validates a hostname
func (a *AbuseIPDB) isValidHostname(hostname string) bool {
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
