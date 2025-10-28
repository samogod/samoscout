package session

import (
	"fmt"
	"io"
	"net/http"
	"github.com/samogod/samoscout/pkg/config"
	"strings"
	"time"
)

var DebugLog func(string, ...interface{})

type Session struct {
	Client *http.Client
	Config *config.Config
	Keys   config.APIKeys
}

type LoggingTransport struct {
	Transport http.RoundTripper
}

func (t *LoggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if DebugLog != nil {
		DebugLog("requesting url: %s", req.URL.String())

		if len(req.Header) > 0 {
			var headers []string
			for k, v := range req.Header {
				if k != "User-Agent" {
					headers = append(headers, fmt.Sprintf("%s: %s", k, strings.Join(v, ", ")))
				}
			}
			if len(headers) > 0 {
				DebugLog("request headers: %s", strings.Join(headers, " | "))
			}
		}
	}

	resp, err := t.Transport.RoundTrip(req)

	if DebugLog != nil {
		sourceName := extractSourceName(req.URL.String())

		if err != nil {
			DebugLog("encountered an error with source %s: %v", sourceName, err)
		} else {
			DebugLog("response for %s: status code %d", req.URL.String(), resp.StatusCode)

			if contentType := resp.Header.Get("Content-Type"); contentType != "" {
				DebugLog("response content-type: %s", contentType)
			}

			if resp.StatusCode >= 400 {
				DebugLog("encountered an error with source %s: unexpected status code %d received from %s",
					sourceName, resp.StatusCode, req.URL.String())

				if resp.Body != nil {
					bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, 500))
					if readErr == nil && len(bodyBytes) > 0 {
						DebugLog("error response body: %s", string(bodyBytes))
					}
				}
			}
		}
	}

	return resp, err
}

func extractSourceName(url string) string {
	parts := strings.Split(url, "://")
	if len(parts) > 1 {
		domain := strings.Split(parts[1], "/")[0]
		domainParts := strings.Split(domain, ".")
		if len(domainParts) > 0 {
			return domainParts[0]
		}
	}

	return "unknown"
}

func New(cfg *config.Config) (*Session, error) {
	baseTransport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
	}

	var transport http.RoundTripper = baseTransport
	if DebugLog != nil {
		transport = &LoggingTransport{Transport: baseTransport}
	}

	client := &http.Client{
		Timeout:   time.Duration(cfg.DefaultSettings.Timeout*3) * time.Second,
		Transport: transport,
	}

	return &Session{
		Client: client,
		Config: cfg,
		Keys:   cfg.APIKeys,
	}, nil
}
