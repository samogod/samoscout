package llm

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/samogod/samoscout/pkg/config"
)

const (
	HuggingFaceRepo = "HadrianSecurity/subwiz"
	ModelFile       = "model.pt"
	TokenizerFile   = "tokenizer.json"
	ConfigFile      = "config.json"
)

type Downloader struct {
	cacheDir string
	client   *http.Client
}

func NewDownloader() *Downloader {
	cacheDir := config.GetLLMCacheDir()
	
	return &Downloader{
		cacheDir: cacheDir,
		client:   &http.Client{},
	}
}

func (d *Downloader) DownloadModel(forceDownload bool) (string, string, error) {
	if err := os.MkdirAll(d.cacheDir, 0755); err != nil {
		return "", "", fmt.Errorf("failed to create cache directory: %w", err)
	}
	
	modelPath := filepath.Join(d.cacheDir, ModelFile)
	tokenizerPath := filepath.Join(d.cacheDir, TokenizerFile)
	configPath := filepath.Join(d.cacheDir, ConfigFile)
	
	if !forceDownload {
		if fileExists(modelPath) && fileExists(tokenizerPath) && fileExists(configPath) {
			return modelPath, tokenizerPath, nil
		}
	}
	
	baseURL := fmt.Sprintf("https://huggingface.co/%s/resolve/main", HuggingFaceRepo)
	
	fmt.Println("[LLM] Downloading AI model files (first run, ~100MB)...")
	
	files := []struct {
		name string
		path string
		url  string
	}{
		{ModelFile, modelPath, baseURL + "/" + ModelFile},
		{TokenizerFile, tokenizerPath, baseURL + "/" + TokenizerFile},
		{ConfigFile, configPath, baseURL + "/" + ConfigFile},
	}
	
	for _, file := range files {
		if forceDownload || !fileExists(file.path) {
			fmt.Printf("[LLM]   downloading %s...\n", file.name)
			if err := d.downloadFile(file.url, file.path); err != nil {
				return "", "", fmt.Errorf("failed to download %s: %w", file.name, err)
			}
		}
	}
	
	fmt.Printf("[LLM] Model cached at %s\n", d.cacheDir)
	
	return modelPath, tokenizerPath, nil
}

func (d *Downloader) downloadFile(url, dest string) error {
	resp, err := d.client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}
	
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	
	_, err = io.Copy(out, resp.Body)
	return err
}

func (d *Downloader) LoadConfig(configPath string) (*ModelConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	
	var config ModelConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	
	return &config, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

