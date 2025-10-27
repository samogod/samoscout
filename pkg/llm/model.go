package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type Model struct {
	scriptPath string
	config     *ModelConfig
}

func LoadModel(modelPath, tokenizerPath string, device string) (*Model, error) {
	configPath := filepath.Join(filepath.Dir(modelPath), ConfigFile)
	downloader := NewDownloader()
	config, err := downloader.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load model config: %w", err)
	}

	_, filename, _, _ := runtime.Caller(0)
	pkgDir := filepath.Dir(filename)
	scriptPath := filepath.Join(pkgDir, "llm_inference.py")

	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("inference script not found at %s", scriptPath)
	}

	return &Model{
		scriptPath: scriptPath,
		config:     config,
	}, nil
}

func (m *Model) Close() error {
	return nil
}

type InferenceRequest struct {
	Subdomains     []string `json:"subdomains"`
	Apex           string   `json:"apex"`
	NumPredictions int      `json:"num_predictions"`
	MaxTokens      int      `json:"max_tokens"`
	Temperature    float64  `json:"temperature"`
	Blocked        []string `json:"blocked"`
}

type InferenceResponse struct {
	Predictions []string `json:"predictions"`
	Error       string   `json:"error,omitempty"`
}

func (m *Model) GenerateDomains(
	ctx context.Context,
	subdomains []string,
	apex string,
	numPredictions int,
	maxTokens int,
	temperature float64,
	blocked []string,
) ([]string, error) {

	req := InferenceRequest{
		Subdomains:     subdomains,
		Apex:           apex,
		NumPredictions: numPredictions,
		MaxTokens:      maxTokens,
		Temperature:    temperature,
		Blocked:        blocked,
	}

	reqJSON, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	cmd := exec.CommandContext(ctx, "python3", m.scriptPath)
	cmd.Stdin = strings.NewReader(string(reqJSON))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to run inference: %w, output: %s", err, string(output))
	}

	var resp InferenceResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w, output: %s", err, string(output))
	}

	if resp.Error != "" {
		return nil, fmt.Errorf("inference error: %s", resp.Error)
	}

	return resp.Predictions, nil
}

func (m *Model) GetConfig() *ModelConfig {
	return m.config
}
