package sources

import (
	"context"
	"crypto/sha1"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"github.com/samogod/samoscout/pkg/session"
	"strings"
)


type Netcraft struct{}

var reNetcraftNext = regexp.MustCompile(`href="(.*host=.*?&.*last=.*?&.*from=.*?)&.*"`)
var netcraftURL = "https://searchdns.netcraft.com"


func (n *Netcraft) Name() string {
	return "netcraft"
}


func (n *Netcraft) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		cookies, err := n.getJSCookies(ctx, netcraftURL, s)
		if err != nil {
			results <- Result{Source: n.Name(), Error: fmt.Errorf("failed to get JS cookies: %w", err)}
			return
		}

		seen := make(map[string]bool)
		headers := map[string]string{"Host": "searchdns.netcraft.com"}
		
		n.enumerate(ctx, netcraftURL+"/?host="+domain, domain, cookies, headers, s, results, seen)
	}()

	return results
}


func (n *Netcraft) sha1Hash(text string) string {
	decodedValue, err := url.QueryUnescape(text)
	if err != nil {
		return ""
	}
	algorithm := sha1.New()
	algorithm.Write([]byte(decodedValue))
	return fmt.Sprintf("%x", algorithm.Sum(nil))
}


func (n *Netcraft) getJSCookies(ctx context.Context, baseURL string, s *session.Session) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	resp, err := s.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "netcraft_js_verification_challenge" {
			
			hashValue := n.sha1Hash(cookie.Value)
			cookieValue := cookie.Name + "=" + cookie.Value + "; netcraft_js_verification_response=" + hashValue
			return cookieValue, nil
		}
	}

	return "", nil
}


func (n *Netcraft) enumerate(ctx context.Context, baseURL string, domain string, cookies string, headers map[string]string, s *session.Session, results chan Result, seen map[string]bool) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		results <- Result{Source: n.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
		return
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	if cookies != "" {
		req.Header.Set("Cookie", cookies)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		results <- Result{Source: n.Name(), Error: fmt.Errorf("API request failed: %w", err)}
		return
	}

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		results <- Result{Source: n.Name(), Error: fmt.Errorf("failed to read response body: %w", err)}
		return
	}

	src := string(body)

	subdomains := n.extractSubdomains(src, domain, seen)
	for _, subdomain := range subdomains {
		select {
		case results <- Result{Source: n.Name(), Value: subdomain, Type: "subdomain"}:
		case <-ctx.Done():
			return
		}
	}

	match := reNetcraftNext.FindStringSubmatch(src)
	if len(match) > 1 {
		nextURL := netcraftURL + match[1]
		n.enumerate(ctx, nextURL, domain, cookies, headers, s, results, seen)
	}
}


func (n *Netcraft) extractSubdomains(html string, targetDomain string, seen map[string]bool) []string {
	var subdomains []string
	
	domainRegex := regexp.MustCompile(`([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}`)
	matches := domainRegex.FindAllString(html, -1)
	
	for _, match := range matches {
		hostname := strings.TrimSpace(strings.ToLower(match))
		
		if n.isValidHostname(hostname) && n.belongsToTargetDomain(hostname, targetDomain) && !seen[hostname] {
			seen[hostname] = true
			subdomains = append(subdomains, hostname)
		}
	}
	
	return subdomains
}


func (n *Netcraft) isValidHostname(hostname string) bool {
	if hostname == "" || len(hostname) < 3 {
		return false
	}
	
	if strings.HasPrefix(hostname, ".") || strings.HasSuffix(hostname, ".") || strings.HasPrefix(hostname, "-") || strings.HasSuffix(hostname, "-") {
		return false
	}
	
	if strings.Contains(hostname, "..") || strings.Contains(hostname, "--") {
		return false
	}
	
	if !strings.Contains(hostname, ".") {
		return false
	}
	
	invalidExtensions := []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".json", ".xml", ".txt", ".pdf", ".zip", ".woff", ".woff2", ".ttf", ".eot"}
	for _, ext := range invalidExtensions {
		if strings.HasSuffix(hostname, ext) {
			return false
		}
	}
	
	parts := strings.Split(hostname, ".")
	for _, part := range parts {
		if part == "" || len(part) > 63 {
			return false
		}
	}
	
	tld := parts[len(parts)-1]
	if len(tld) < 2 || !regexp.MustCompile(`^[a-z]{2,}$`).MatchString(tld) {
		return false
	}
	
	return true
}
func (n *Netcraft) belongsToTargetDomain(hostname, targetDomain string) bool {
	if hostname == targetDomain {
		return true
	}
	
	return strings.HasSuffix(hostname, "."+targetDomain)
}

