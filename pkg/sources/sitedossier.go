package sources

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"regexp"
	"samoscout/pkg/session"
	"strings"
	"time"
)


type SiteDossier struct{}


var reNext = regexp.MustCompile(`<a href="([A-Za-z0-9/.]+)"><b>`)


const (
	minDelay = 4 * time.Second
	maxDelay = 7 * time.Second
)


func (s *SiteDossier) Name() string {
	return "sitedossier"
}


func (s *SiteDossier) Run(ctx context.Context, domain string, session *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		seen := make(map[string]bool)
		baseURL := fmt.Sprintf("http://www.sitedossier.com/parentdomain/%s", domain)
		
		
		select {
		case <-time.After(1 * time.Second):
			
		case <-ctx.Done():
			return
		}
		
		s.enumerate(ctx, baseURL, session, results, seen)
	}()

	return results
}


func (s *SiteDossier) enumerate(ctx context.Context, baseURL string, session *session.Session, results chan Result, seen map[string]bool) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		results <- Result{Source: s.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
		return
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	resp, err := session.Client.Do(req)
	isNotFound := resp != nil && resp.StatusCode == http.StatusNotFound
	if err != nil && !isNotFound {
		results <- Result{Source: s.Name(), Error: fmt.Errorf("API request failed: %w", err)}
		return
	}

	if resp == nil {
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		results <- Result{Source: s.Name(), Error: fmt.Errorf("failed to read response body: %w", err)}
		resp.Body.Close()
		return
	}
	resp.Body.Close()

	
	src := string(body)
	subdomains := s.extractSubdomains(src, seen)
	
	for _, subdomain := range subdomains {
		select {
		case results <- Result{Source: s.Name(), Value: subdomain, Type: "subdomain"}:
		case <-ctx.Done():
			return
		}
	}

	
	match := reNext.FindStringSubmatch(src)
	if len(match) > 0 {
		nextURL := fmt.Sprintf("http://www.sitedossier.com%s", match[1])
		
		
		delay := s.getRandomDelay()
		
		select {
		case <-time.After(delay):
			
		case <-ctx.Done():
			return
		}
		
		s.enumerate(ctx, nextURL, session, results, seen)
	}
}



func (s *SiteDossier) extractSubdomains(html string, seen map[string]bool) []string {
	var subdomains []string
	
	
	
	urlRegex := regexp.MustCompile(`<a[^>]*href="/site/[^"]*"[^>]*>http://([a-zA-Z0-9.-]+)/</a>`)
	urlMatches := urlRegex.FindAllStringSubmatch(html, -1)
	
	for _, match := range urlMatches {
		if len(match) > 1 {
			hostname := strings.TrimSpace(strings.ToLower(match[1]))
			
			
			if s.isValidHostname(hostname) && !seen[hostname] {
				seen[hostname] = true
				subdomains = append(subdomains, hostname)
			}
		}
	}
	
	
	
	hrefRegex := regexp.MustCompile(`<a[^>]*href="/site/([a-zA-Z0-9.-]+)"[^>]*>`)
	hrefMatches := hrefRegex.FindAllStringSubmatch(html, -1)
	
	for _, match := range hrefMatches {
		if len(match) > 1 {
			hostname := strings.TrimSpace(strings.ToLower(match[1]))
			
			
			if s.isValidHostname(hostname) && !seen[hostname] {
				seen[hostname] = true
				subdomains = append(subdomains, hostname)
			}
		}
	}
	
	
	if len(subdomains) == 0 {
		generalRegex := regexp.MustCompile(`([a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+)`)
		generalMatches := generalRegex.FindAllStringSubmatch(html, -1)
		
		for _, match := range generalMatches {
			if len(match) > 1 {
				hostname := strings.TrimSpace(strings.ToLower(match[1]))
				
				
				if s.isValidHostname(hostname) && !seen[hostname] {
					seen[hostname] = true
					subdomains = append(subdomains, hostname)
				}
			}
		}
	}
	
	return subdomains
}


func (s *SiteDossier) getRandomDelay() time.Duration {
	
	delayRange := maxDelay - minDelay
	randomSeconds := rand.Float64() * delayRange.Seconds()
	return minDelay + time.Duration(randomSeconds*float64(time.Second))
}


func (s *SiteDossier) isValidHostname(hostname string) bool {
	if hostname == "" {
		return false
	}
	
	
	if strings.Contains(hostname, "..") || strings.HasPrefix(hostname, ".") || strings.HasSuffix(hostname, ".") {
		return false
	}
	
	
	if !strings.Contains(hostname, ".") {
		return false
	}
	
	
	for _, char := range hostname {
		if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '.' || char == '-') {
			return false
		}
	}
	
	return true
}
