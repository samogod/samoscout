package sources

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"samoscout/pkg/session"
	"strconv"
	"strings"
)


type DNSDB struct{}

const urlBase string = "https://api.dnsdb.info/dnsdb/v2"


type DNSDBRateResponse struct {
	Rate DNSDBRate `json:"rate"`
}

type DNSDBRate struct {
	OffsetMax json.Number `json:"offset_max"`
}


type DNSDBSafResponse struct {
	Condition string     `json:"cond"`
	Obj       DNSDBObj   `json:"obj"`
	Msg       string     `json:"msg"`
}

type DNSDBObj struct {
	Name string `json:"rrname"`
}


func (d *DNSDB) Name() string {
	return "dnsdb"
}


func (d *DNSDB) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		if s.Keys.DNSDB == "" {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("DNSDB API key not configured")}
			return
		}

		
		offsetMax, err := d.getMaxOffset(ctx, s)
		if err != nil {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("failed to get rate limit: %w", err)}
			return
		}

		
		err = d.streamSubdomains(ctx, domain, s, offsetMax, results)
		if err != nil {
			results <- Result{Source: d.Name(), Error: err}
		}
	}()

	return results
}


func (d *DNSDB) getMaxOffset(ctx context.Context, s *session.Session) (uint64, error) {
	var offsetMax uint64
	
	url := fmt.Sprintf("%s/rate_limit", urlBase)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return offsetMax, fmt.Errorf("failed to create rate limit request: %w", err)
	}

	
	req.Header.Set("X-API-KEY", s.Keys.DNSDB)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	resp, err := s.Client.Do(req)
	if err != nil {
		return offsetMax, fmt.Errorf("failed to execute rate limit request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return offsetMax, fmt.Errorf("rate limit HTTP error: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return offsetMax, fmt.Errorf("failed to read rate limit response: %w", err)
	}

	var rateResp DNSDBRateResponse
	if err := json.Unmarshal(data, &rateResp); err != nil {
		return offsetMax, fmt.Errorf("failed to decode rate limit JSON: %w", err)
	}

	
	if rateResp.Rate.OffsetMax.String() != "n/a" {
		offsetMax, err = strconv.ParseUint(rateResp.Rate.OffsetMax.String(), 10, 64)
		if err != nil {
			return offsetMax, fmt.Errorf("failed to parse offset max: %w", err)
		}
	}

	return offsetMax, nil
}


func (d *DNSDB) streamSubdomains(ctx context.Context, domain string, s *session.Session, offsetMax uint64, results chan<- Result) error {
	path := fmt.Sprintf("lookup/rrset/name/*.%s", domain)
	urlTemplate := fmt.Sprintf("%s/%s?", urlBase, path)
	
	queryParams := url.Values{}
	queryParams.Add("limit", "0")
	queryParams.Add("swclient", "samoscout")

	seen := make(map[string]bool)
	var totalResults uint64

	for {
		url := urlTemplate + queryParams.Encode()
		
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("failed to create DNSDB request: %w", err)
		}
		
		req.Header.Set("X-API-KEY", s.Keys.DNSDB)
		req.Header.Set("Accept", "application/x-ndjson")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

		resp, err := s.Client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to execute DNSDB request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == 401 {
			return fmt.Errorf("invalid DNSDB API key")
		}

		if resp.StatusCode == 429 {
			return fmt.Errorf("DNSDB rate limit exceeded")
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("DNSDB HTTP error: %d", resp.StatusCode)
		}

		
		var respCond string
		reader := bufio.NewReader(resp.Body)
		
		for {
			line, err := reader.ReadBytes('\n')
			if err == io.EOF {
				break
			} else if err != nil {
				return fmt.Errorf("failed to read DNSDB response: %w", err)
			}

			var response DNSDBSafResponse
			if err := json.Unmarshal(line, &response); err != nil {
				
				continue
			}

			
			
			respCond = response.Condition
			
			if respCond == "" || respCond == "ongoing" {
				
				if response.Obj.Name != "" {
					hostname := strings.TrimSuffix(response.Obj.Name, ".")
					hostname = strings.ToLower(strings.TrimSpace(hostname))
					
					
					if hostname != "" && hostname != domain && 
					   strings.HasSuffix(hostname, "."+domain) && 
					   !seen[hostname] {
						seen[hostname] = true
						totalResults++
						
						select {
						case results <- Result{Source: d.Name(), Value: hostname, Type: "subdomain"}:
						case <-ctx.Done():
							return nil
						}
					}
				}
			} else if respCond != "begin" {
				
				break
			}
		}

		
		if respCond == "limited" {
			
			if offsetMax != 0 && totalResults <= offsetMax {
				queryParams.Set("offset", strconv.FormatUint(totalResults, 10))
				continue
			}
		} else if respCond != "succeeded" {
			
			return fmt.Errorf("DNSDB terminated with condition: %s", respCond)
		}

		
		break
	}

	return nil
}
