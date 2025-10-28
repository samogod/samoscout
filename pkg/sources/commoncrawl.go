package sources

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"github.com/samogod/samoscout/pkg/session"
	"strconv"
	"strings"
	"time"
)


type CommonCrawl struct{}


type IndexResponse struct {
	ID     string `json:"id"`
	APIURL string `json:"cdx-api"`
}

const (
	indexURL     = "https://index.commoncrawl.org/collinfo.json"
	maxYearsBack = 5
)


func (c *CommonCrawl) Name() string {
	return "commoncrawl"
}


func (c *CommonCrawl) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		indexes, err := c.getIndexes(ctx, s)
		if err != nil {
			results <- Result{Source: c.Name(), Error: fmt.Errorf("failed to get indexes: %w", err)}
			return
		}

		
		searchIndexes := c.getSearchIndexes(indexes)

		
		seen := make(map[string]bool)
		for _, apiURL := range searchIndexes {
			select {
			case <-ctx.Done():
				return
			default:
				c.searchInIndex(ctx, apiURL, domain, s, seen, results)
			}
		}
	}()

	return results
}


func (c *CommonCrawl) getIndexes(ctx context.Context, s *session.Session) ([]IndexResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, indexURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "application/json")

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	
	var indexes []IndexResponse
	if err := json.NewDecoder(resp.Body).Decode(&indexes); err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %w", err)
	}

	return indexes, nil
}


func (c *CommonCrawl) getSearchIndexes(indexes []IndexResponse) map[string]string {
	currentYear := time.Now().Year()
	years := make([]string, 0)
	
	
	for i := 0; i < maxYearsBack; i++ {
		years = append(years, strconv.Itoa(currentYear-i))
	}

	searchIndexes := make(map[string]string)
	for _, year := range years {
		for _, index := range indexes {
			if strings.Contains(index.ID, year) {
				if _, ok := searchIndexes[year]; !ok {
					searchIndexes[year] = index.APIURL
					break
				}
			}
		}
	}

	return searchIndexes
}


func (c *CommonCrawl) searchInIndex(ctx context.Context, apiURL, domain string, s *session.Session, seen map[string]bool, results chan<- Result) {
	
	for {
		select {
		case <-ctx.Done():
			return
		default:
			
			searchURL := fmt.Sprintf("%s?url=*.%s", apiURL, domain)
			
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, nil)
			if err != nil {
				results <- Result{Source: c.Name(), Error: fmt.Errorf("failed to create search request: %w", err)}
				return
			}

			
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
			req.Header.Set("Host", "index.commoncrawl.org")

			resp, err := s.Client.Do(req)
			if err != nil {
				results <- Result{Source: c.Name(), Error: fmt.Errorf("failed to execute search request: %w", err)}
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				results <- Result{Source: c.Name(), Error: fmt.Errorf("search HTTP error: %d", resp.StatusCode)}
				return
			}

			
			scanner := bufio.NewScanner(resp.Body)
			for scanner.Scan() {
				line := scanner.Text()
				if line == "" {
					continue
				}

				
				line, _ = url.QueryUnescape(line)
				
				
				subdomains := c.extractSubdomains(line, domain)
				
				for _, subdomain := range subdomains {
					if subdomain != "" && !seen[subdomain] {
						seen[subdomain] = true
						
						select {
						case results <- Result{Source: c.Name(), Value: subdomain, Type: "subdomain"}:
						case <-ctx.Done():
							return
						}
					}
				}
			}
			
			
			return
		}
	}
}


func (c *CommonCrawl) extractSubdomains(line, domain string) []string {
	var subdomains []string
	
	
	
	parts := strings.Fields(line)
	
	for _, part := range parts {
		
		hostnames := c.extractHostnamesFromPart(part, domain)
		subdomains = append(subdomains, hostnames...)
	}
	
	return subdomains
}


func (c *CommonCrawl) extractHostnamesFromPart(part, domain string) []string {
	var hostnames []string
	
	
	if strings.Contains(part, "://") {
		if u, err := url.Parse(part); err == nil && u.Host != "" {
			hostname := c.cleanHostname(u.Host, domain)
			if hostname != "" {
				hostnames = append(hostnames, hostname)
			}
		}
	}
	
	
	if strings.Contains(part, "."+domain) {
		
		segments := strings.FieldsFunc(part, func(r rune) bool {
			return r == ' ' || r == '\t' || r == ',' || r == ';' || r == '(' || r == ')' || 
				   r == '[' || r == ']' || r == '{' || r == '}' || r == '"' || r == '\'' ||
				   r == '?' || r == '#' || r == '&' || r == '='
		})
		
		for _, segment := range segments {
			if strings.Contains(segment, "."+domain) {
				hostname := c.cleanHostname(segment, domain)
				if hostname != "" {
					hostnames = append(hostnames, hostname)
				}
			}
		}
	}
	
	return hostnames
}


func (c *CommonCrawl) cleanHostname(raw, domain string) string {
	hostname := strings.ToLower(strings.TrimSpace(raw))
	
	
	if strings.Contains(hostname, "://") {
		parts := strings.Split(hostname, "://")
		if len(parts) > 1 {
			hostname = parts[1]
		}
	}
	
	
	hostname = strings.TrimPrefix(hostname, "25")
	hostname = strings.TrimPrefix(hostname, "2f")
	
	
	if slashIndex := strings.Index(hostname, "/"); slashIndex > 0 {
		hostname = hostname[:slashIndex]
	}
	if questionIndex := strings.Index(hostname, "?"); questionIndex > 0 {
		hostname = hostname[:questionIndex]
	}
	
	
	if colonIndex := strings.LastIndex(hostname, ":"); colonIndex > 0 {
		if portPart := hostname[colonIndex+1:]; isNumeric(portPart) {
			hostname = hostname[:colonIndex]
		}
	}
	
	
	hostname = strings.Trim(hostname, ".,;:!?()[]{}\"'/\\")
	
	
	if hostname != "" && hostname != domain && 
	   strings.HasSuffix(hostname, "."+domain) && 
	   isValidHostname(hostname) {
		return hostname
	}
	
	return ""
}


func isNumeric(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}


func isValidHostname(hostname string) bool {
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

	return true
}
