package llm

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/samogod/samoscout/pkg/config"
)

//go:embed llm_inference.py gpt_model.py
var pythonScripts embed.FS

type Model struct {
	scriptPath string
	config     *ModelConfig
}

func extractPythonScripts() (string, error) {
	scriptsDir := filepath.Join(config.GetCacheDir(), "python_scripts")
	
	if err := os.MkdirAll(scriptsDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create scripts directory: %w", err)
	}

	scripts := []string{"llm_inference.py", "gpt_model.py"}
	
	for _, scriptName := range scripts {
		scriptPath := filepath.Join(scriptsDir, scriptName)
		
		content, err := pythonScripts.ReadFile(scriptName)
		if err != nil {
			return "", fmt.Errorf("failed to read embedded script %s: %w", scriptName, err)
		}
		
		if err := os.WriteFile(scriptPath, content, 0755); err != nil {
			return "", fmt.Errorf("failed to write script %s: %w", scriptName, err)
		}
	}
	
	return filepath.Join(scriptsDir, "llm_inference.py"), nil
}

func LoadModel(modelPath, tokenizerPath string, device string) (*Model, error) {
	configPath := filepath.Join(filepath.Dir(modelPath), ConfigFile)
	downloader := NewDownloader()
	config, err := downloader.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load model config: %w", err)
	}

	scriptPath, err := extractPythonScripts()
	if err != nil {
		return nil, fmt.Errorf("failed to extract Python scripts: %w", err)
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

func getPythonCommand() string {
	if runtime.GOOS == "windows" {
		return "python"
	}
	return "python3"
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

	pythonCmd := getPythonCommand()
	cmd := exec.CommandContext(ctx, pythonCmd, m.scriptPath)
	cmd.Stdin = strings.NewReader(string(reqJSON))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to run inference with '%s': %w\nOutput: %s\nHint: Ensure Python 3.7+ is installed and in PATH", pythonCmd, err, string(output))
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
