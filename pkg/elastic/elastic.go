package elastic

import (
    "bufio"
    "context"
    "errors"
    "fmt"
    "os"
    "strings"

    es8 "github.com/elastic/go-elasticsearch/v8"
    "github.com/elastic/go-elasticsearch/v8/esutil"
)

type Config struct {
    URL      string
    Username string
    Password string
    Index    string
}

type Client struct {
    es    *es8.Client
    index string
}

func New(cfg Config) (*Client, error) {
    if cfg.URL == "" {
        return nil, errors.New("elasticsearch URL is required")
    }
    index := cfg.Index
    if strings.TrimSpace(index) == "" {
        index = "samoscout_httpx"
    }

    es, err := es8.NewClient(es8.Config{
        Addresses: []string{cfg.URL},
        Username:  cfg.Username,
        Password:  cfg.Password,
    })
    if err != nil {
        return nil, fmt.Errorf("failed to create elasticsearch client: %w", err)
    }

    // Lightweight ping
    if _, err := es.Info(); err != nil {
        return nil, fmt.Errorf("failed to connect to elasticsearch: %w", err)
    }

    return &Client{es: es, index: index}, nil
}

func (c *Client) IndexJSONLinesFile(ctx context.Context, filename string) error {
    f, err := os.Open(filename)
    if err != nil {
        return fmt.Errorf("failed to open jsonl file: %w", err)
    }
    defer f.Close()

    bi, err := esutil.NewBulkIndexer(esutil.BulkIndexerConfig{
        Client:     c.es,
        Index:      c.index,
        NumWorkers: 4,
    })
    if err != nil {
        return fmt.Errorf("failed to create bulk indexer: %w", err)
    }

    scanner := bufio.NewScanner(f)
    buf := make([]byte, 0, 1024*1024)
    scanner.Buffer(buf, 8*1024*1024)

    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line == "" {
            continue
        }

        item := esutil.BulkIndexerItem{
            Action:     "index",
            DocumentID: "",
            Body:       strings.NewReader(line),
            OnFailure: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem, err error) {
            },
        }
        if err := bi.Add(ctx, item); err != nil {
            return fmt.Errorf("bulk add failed: %w", err)
        }
    }
    if err := scanner.Err(); err != nil {
        return fmt.Errorf("scanner error: %w", err)
    }

    if err := bi.Close(ctx); err != nil {
        return fmt.Errorf("bulk indexer close failed: %w", err)
    }

    return nil
}


