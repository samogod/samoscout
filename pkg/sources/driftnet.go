package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"github.com/samogod/samoscout/pkg/session"
	"strings"
	"sync"
	"sync/atomic"
)


type Driftnet struct{}

const (
	
	baseURL = "https://api.driftnet.io/v1/"
	
	summaryLimit = 10000
)


type DriftnetEndpointConfig struct {
	
	Endpoint string
	
	Param string
	
	Context string
}


type DriftnetSummaryResponse struct {
	Summary struct {
		Other  int            `json:"other"`
		Values map[string]int `json:"values"`
	} `json:"summary"`
}


var endpoints = []DriftnetEndpointConfig{
	{"ct/log", "field=host:", "cert-dns-name"},
	{"scan/protocols", "field=host:", "cert-dns-name"},
	{"scan/domains", "field=host:", "cert-dns-name"},
	{"domain/rdns", "host=", "dns-ptr"},
}


func (d *Driftnet) Name() string {
	return "driftnet"
}


func (d *Driftnet) Run(ctx context.Context, domain string, s *session.Session) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		
		if s.Keys.Driftnet == "" {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("Driftnet API key not configured")}
			return
		}

		
		var wg sync.WaitGroup
		var errors atomic.Int32
		var totalResults atomic.Int32
		dedupe := sync.Map{}

		
		wg.Add(len(endpoints))
		for i := range endpoints {
			go d.runSubsource(ctx, domain, s, results, &wg, &dedupe, &errors, &totalResults, endpoints[i])
		}

		
		wg.Wait()
	}()

	return results
}


func (d *Driftnet) runSubsource(ctx context.Context, domain string, s *session.Session, results chan<- Result, wg *sync.WaitGroup, dedupe *sync.Map, errors *atomic.Int32, totalResults *atomic.Int32, epConfig DriftnetEndpointConfig) {
	defer wg.Done()

	
	requestURL := fmt.Sprintf("%s%s?%s%s&summarize=host&summary_context=%s&summary_limit=%d", 
		baseURL, epConfig.Endpoint, epConfig.Param, url.QueryEscape(domain), epConfig.Context, summaryLimit)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		results <- Result{Source: d.Name(), Error: fmt.Errorf("failed to create request for %s: %w", epConfig.Endpoint, err)}
		errors.Add(1)
		return
	}

	
	req.Header.Set("Authorization", "Bearer "+s.Keys.Driftnet)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	resp, err := s.Client.Do(req)
	if err != nil {
		
		if resp == nil || resp.StatusCode != http.StatusNoContent {
			results <- Result{Source: d.Name(), Error: fmt.Errorf("failed to execute request for %s: %w", epConfig.Endpoint, err)}
			errors.Add(1)
		}
		return
	}
	defer resp.Body.Close()

	
	if resp.StatusCode == 401 {
		results <- Result{Source: d.Name(), Error: fmt.Errorf("invalid Driftnet API key")}
		errors.Add(1)
		return
	}

	if resp.StatusCode == 429 {
		results <- Result{Source: d.Name(), Error: fmt.Errorf("Driftnet rate limit exceeded")}
		errors.Add(1)
		return
	}

	
	if resp.StatusCode == 204 {
		return
	}

	if resp.StatusCode != http.StatusOK {
		results <- Result{Source: d.Name(), Error: fmt.Errorf("HTTP error from %s: %d", epConfig.Endpoint, resp.StatusCode)}
		errors.Add(1)
		return
	}

	
	var summary DriftnetSummaryResponse
	if err := json.NewDecoder(resp.Body).Decode(&summary); err != nil {
		results <- Result{Source: d.Name(), Error: fmt.Errorf("failed to decode JSON from %s: %w", epConfig.Endpoint, err)}
		errors.Add(1)
		return
	}

	
	for subdomain := range summary.Summary.Values {
		hostname := strings.TrimSpace(strings.ToLower(subdomain))
		
		
		if hostname != "" && hostname != domain && strings.HasSuffix(hostname, "."+domain) {
			
			if _, present := dedupe.LoadOrStore(hostname, true); !present {
				totalResults.Add(1)
				
				select {
				case results <- Result{Source: d.Name(), Value: hostname, Type: "subdomain"}:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}
