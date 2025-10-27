package llm

import (
	"regexp"
	"strings"
)

var (
	validSubdomainRe = regexp.MustCompile(
		`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`,
	)
	
	validSubdomainStartRe = regexp.MustCompile(
		`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)?$`,
	)
)

type Validator struct{}

func NewValidator() *Validator {
	return &Validator{}
}

func (v *Validator) IsValidSubdomain(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	
	if s == "" || len(s) > 253 {
		return false
	}
	
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return false
	}
	
	if strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") {
		return false
	}
	
	if strings.Contains(s, "..") || strings.Contains(s, "--") {
		return false
	}
	
	return validSubdomainRe.MatchString(s)
}

func (v *Validator) IsValidSubdomainStart(s string) bool {
	s = strings.TrimSpace(s)
	return validSubdomainStartRe.MatchString(s)
}

func (v *Validator) ExtractSubdomain(fullDomain, apex string) (string, bool) {
	fullDomain = strings.ToLower(strings.TrimSpace(fullDomain))
	apex = strings.ToLower(strings.TrimSpace(apex))
	
	if fullDomain == "" || apex == "" {
		return "", false
	}
	
	fullDomain = strings.TrimPrefix(fullDomain, "*.")
	
	if fullDomain == apex {
		return "", true
	}
	
	if !strings.HasSuffix(fullDomain, "."+apex) {
		return "", false
	}
	
	subdomain := strings.TrimSuffix(fullDomain, "."+apex)
	
	if !v.IsValidSubdomain(subdomain) {
		return "", false
	}
	
	return subdomain, true
}

func (v *Validator) NormalizeSubdomains(domains []string, apex string) []string {
	seen := make(map[string]bool)
	result := []string{}
	
	for _, domain := range domains {
		normalized := strings.ToLower(strings.TrimSpace(domain))
		if normalized == "" {
			continue
		}
		
		normalized = strings.TrimPrefix(normalized, "*.")
		
		if !seen[normalized] && strings.HasSuffix(normalized, apex) {
			seen[normalized] = true
			result = append(result, normalized)
		}
	}
	
	return result
}

func (v *Validator) FilterBlockedDomains(predictions []string, blocked map[string]bool) []string {
	result := []string{}
	
	for _, pred := range predictions {
		normalized := strings.ToLower(strings.TrimSpace(pred))
		if !blocked[normalized] {
			result = append(result, pred)
		}
	}
	
	return result
}

