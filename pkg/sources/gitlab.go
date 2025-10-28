package sources

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"github.com/samogod/samoscout/pkg/session"
	"strings"
	"sync"
)


type GitLab struct{}


type GitLabItem struct {
	Data      string `json:"data"`
	ProjectId int    `json:"project_id"`
	Path      string `json:"path"`
	Ref       string `json:"ref"`
}


func (g *GitLab) Name() string {
	return "gitlab"
}


func (g *GitLab) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		if s.Keys.GitLab == "" {
			results <- Result{Source: g.Name(), Error: fmt.Errorf("GitLab API key not configured")}
			return
		}

		
		domainRegex := g.createDomainRegexp(domain)

		
		searchURL := fmt.Sprintf("https://gitlab.com/api/v4/search?scope=blobs&search=%s&per_page=100", domain)
		
		
		g.enumerate(ctx, searchURL, domainRegex, s, results)
	}()

	return results
}


func (g *GitLab) enumerate(ctx context.Context, searchURL string, domainRegex *regexp.Regexp, s *session.Session, results chan<- Result) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, nil)
	if err != nil {
		results <- Result{Source: g.Name(), Error: fmt.Errorf("failed to create search request: %w", err)}
		return
	}

	
	req.Header.Set("PRIVATE-TOKEN", s.Keys.GitLab)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "application/json")

	resp, err := s.Client.Do(req)
	if err != nil {
		results <- Result{Source: g.Name(), Error: fmt.Errorf("failed to execute search request: %w", err)}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		results <- Result{Source: g.Name(), Error: fmt.Errorf("invalid GitLab API key")}
		return
	}

	if resp.StatusCode == 429 {
		results <- Result{Source: g.Name(), Error: fmt.Errorf("GitLab rate limit exceeded")}
		return
	}

	if resp.StatusCode != http.StatusOK {
		results <- Result{Source: g.Name(), Error: fmt.Errorf("GitLab search HTTP error: %d", resp.StatusCode)}
		return
	}

	
	var items []GitLabItem
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		results <- Result{Source: g.Name(), Error: fmt.Errorf("failed to decode GitLab search JSON: %w", err)}
		return
	}

	
	var wg sync.WaitGroup
	seen := sync.Map{}

	for _, item := range items {
		wg.Add(1)
		go func(item GitLabItem) {
			defer wg.Done()
			g.processFile(ctx, item, domainRegex, s, results, &seen)
		}(item)
	}

	
	g.processNextPage(ctx, resp, domainRegex, s, results)

	
	wg.Wait()
}


func (g *GitLab) processFile(ctx context.Context, item GitLabItem, domainRegex *regexp.Regexp, s *session.Session, results chan<- Result, seen *sync.Map) {
	
	fileURL := fmt.Sprintf("https://gitlab.com/api/v4/projects/%d/repository/files/%s/raw?ref=%s", 
		item.ProjectId, url.QueryEscape(item.Path), item.Ref)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fileURL, nil)
	if err != nil {
		return 
	}

	
	req.Header.Set("PRIVATE-TOKEN", s.Keys.GitLab)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	resp, err := s.Client.Do(req)
	if err != nil {
		return 
	}
	defer resp.Body.Close()

	
	if resp.StatusCode == http.StatusNotFound {
		return
	}

	if resp.StatusCode != http.StatusOK {
		return 
	}

	
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		line := scanner.Text()
		if line == "" {
			continue
		}

		
		matches := domainRegex.FindAllString(line, -1)
		for _, match := range matches {
			hostname := strings.TrimSpace(strings.ToLower(match))
			
			
			if hostname != "" && g.isValidSubdomain(hostname) {
				if _, exists := seen.LoadOrStore(hostname, true); !exists {
					select {
					case results <- Result{Source: g.Name(), Value: hostname, Type: "subdomain"}:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}
}


func (g *GitLab) processNextPage(ctx context.Context, resp *http.Response, domainRegex *regexp.Regexp, s *session.Session, results chan<- Result) {
	
	linkHeader := resp.Header.Get("Link")
	if linkHeader == "" {
		return
	}

	
	links := strings.Split(linkHeader, ",")
	for _, link := range links {
		if strings.Contains(link, `rel="next"`) {
			
			start := strings.Index(link, "<")
			end := strings.Index(link, ">")
			if start != -1 && end != -1 && end > start {
				nextURL := link[start+1 : end]
				
				
				if decodedURL, err := url.QueryUnescape(nextURL); err == nil {
					
					g.enumerate(ctx, decodedURL, domainRegex, s, results)
				}
			}
			break
		}
	}
}


func (g *GitLab) createDomainRegexp(domain string) *regexp.Regexp {
	
	escapedDomain := strings.ReplaceAll(domain, ".", "\\.")
	
	
	pattern := fmt.Sprintf(`(\w[a-zA-Z0-9][a-zA-Z0-9\-\.]*%s)`, escapedDomain)
	
	return regexp.MustCompile(pattern)
}


func (g *GitLab) isValidSubdomain(subdomain string) bool {
	if len(subdomain) == 0 || len(subdomain) > 253 {
		return false
	}

	
	if strings.HasPrefix(subdomain, ".") || strings.HasSuffix(subdomain, ".") {
		return false
	}

	if strings.Contains(subdomain, "..") {
		return false
	}

	
	if !strings.Contains(subdomain, ".") {
		return false
	}

	return true
}
