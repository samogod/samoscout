package sources

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"github.com/samogod/samoscout/pkg/session"
	"strings"

	
	_ "github.com/lib/pq"
)


type Crtsh struct{}


type CrtshResult struct {
	ID        int    `json:"id"`
	NameValue string `json:"name_value"`
}


func (c *Crtsh) Name() string {
	return "crtsh"
}


func (c *Crtsh) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		count := c.getSubdomainsFromSQL(ctx, domain, results)
		if count > 0 {
			
			return
		}

		
		c.getSubdomainsFromHTTP(ctx, domain, s, results)
	}()

	return results
}


func (c *Crtsh) getSubdomainsFromSQL(ctx context.Context, domain string, results chan<- Result) int {
	
	db, err := sql.Open("postgres", "host=crt.sh user=guest dbname=certwatch sslmode=disable binary_parameters=yes")
	if err != nil {
		
		return 0
	}
	defer db.Close()

	
	limitClause := "LIMIT 10000" 
	query := fmt.Sprintf(`WITH ci AS (
				SELECT min(sub.CERTIFICATE_ID) ID,
					min(sub.ISSUER_CA_ID) ISSUER_CA_ID,
					array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES,
					x509_commonName(sub.CERTIFICATE) COMMON_NAME,
					x509_notBefore(sub.CERTIFICATE) NOT_BEFORE,
					x509_notAfter(sub.CERTIFICATE) NOT_AFTER,
					encode(x509_serialNumber(sub.CERTIFICATE), 'hex') SERIAL_NUMBER
					FROM (SELECT *
							FROM certificate_and_identities cai
							WHERE plainto_tsquery('certwatch', $1) @@ identities(cai.CERTIFICATE)
								AND cai.NAME_VALUE ILIKE ('%%%%' || $1 || '%%%%')
								%s
						) sub
					GROUP BY sub.CERTIFICATE
			)
			SELECT array_to_string(ci.NAME_VALUES, chr(10)) NAME_VALUE
				FROM ci
						LEFT JOIN LATERAL (
							SELECT min(ctle.ENTRY_TIMESTAMP) ENTRY_TIMESTAMP
								FROM ct_log_entry ctle
								WHERE ctle.CERTIFICATE_ID = ci.ID
						) le ON TRUE,
					ca
				WHERE ci.ISSUER_CA_ID = ca.ID
				ORDER BY le.ENTRY_TIMESTAMP DESC NULLS LAST;`, limitClause)

	rows, err := db.QueryContext(ctx, query, domain)
	if err != nil {
		
		return 0
	}
	defer rows.Close()

	if err := rows.Err(); err != nil {
		return 0
	}

	var count int
	seen := make(map[string]bool)

	
	for rows.Next() {
		var data string
		err := rows.Scan(&data)
		if err != nil {
			continue
		}

		count++
		
		subdomains := strings.Split(data, "\n")
		for _, subdomain := range subdomains {
			cleanSub := c.extractSubdomain(subdomain, domain)
			if cleanSub != "" && !seen[cleanSub] {
				seen[cleanSub] = true
				
				select {
				case results <- Result{Source: c.Name(), Value: cleanSub, Type: "subdomain"}:
				case <-ctx.Done():
					return count
				}
			}
		}
	}

	return count
}


func (c *Crtsh) getSubdomainsFromHTTP(ctx context.Context, domain string, s *session.Session, results chan<- Result) {
	
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		results <- Result{Source: c.Name(), Error: fmt.Errorf("failed to create request: %w", err)}
		return
	}

	
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "application/json")

	resp, err := s.Client.Do(req)
	if err != nil {
		results <- Result{Source: c.Name(), Error: fmt.Errorf("failed to execute request: %w", err)}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		results <- Result{Source: c.Name(), Error: fmt.Errorf("HTTP error: %d", resp.StatusCode)}
		return
	}

	
	var crtResults []CrtshResult
	if err := json.NewDecoder(resp.Body).Decode(&crtResults); err != nil {
		results <- Result{Source: c.Name(), Error: fmt.Errorf("failed to decode JSON: %w", err)}
		return
	}

	
	seen := make(map[string]bool)
	for _, crtResult := range crtResults {
		
		subdomains := strings.Split(crtResult.NameValue, "\n")
		for _, subdomain := range subdomains {
			cleanSub := c.extractSubdomain(subdomain, domain)
			if cleanSub != "" && !seen[cleanSub] {
				seen[cleanSub] = true

				select {
				case results <- Result{Source: c.Name(), Value: cleanSub, Type: "subdomain"}:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}


func (c *Crtsh) extractSubdomain(raw, domain string) string {
	
	subdomain := strings.TrimSpace(raw)
	subdomain = strings.ToLower(subdomain)
	
	
	subdomain = strings.TrimPrefix(subdomain, "*.")
	
	
	if subdomain == "" || subdomain == domain || !c.isValidSubdomain(subdomain) {
		return ""
	}
	
	
	if !strings.HasSuffix(subdomain, "."+domain) {
		return ""
	}
	
	return subdomain
}


func (c *Crtsh) isValidSubdomain(subdomain string) bool {
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
