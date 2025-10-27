package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

var DebugLog func(string, ...interface{})

type Config struct {
	APIKeys           APIKeys           `yaml:"api_keys"`
	DefaultSettings   DefaultSettings   `yaml:"default_settings"`
	ActiveEnumeration ActiveEnumeration `yaml:"active_enumeration"`
	LLMEnumeration    LLMEnumeration    `yaml:"llm_enumeration"`
	Database          Database          `yaml:"database"`
}

type APIKeys struct {
	Chaos           string `yaml:"chaos"`
	Censys          string `yaml:"censys"`
	VirusTotal      string `yaml:"virustotal"`
	SecurityTrails  string `yaml:"securitytrails"`
	Shodan          string `yaml:"shodan"`
	GitHub          string `yaml:"github"`
	BeVigil         string `yaml:"bevigil"`
	BufferOver      string `yaml:"bufferover"`
	BuiltWith       string `yaml:"builtwith"`
	C99             string `yaml:"c99"`
	CertSpotter     string `yaml:"certspotter"`
	Chinaz          string `yaml:"chinaz"`
	Cloudflare      string `yaml:"cloudflare"`
	DigitalYama     string `yaml:"digitalyama"`
	DNSDB           string `yaml:"dnsdb"`
	DNSDumpster     string `yaml:"dnsdumpster"`
	DNSRepo         string `yaml:"dnsrepo"`
	DNSArchive      string `yaml:"dnsarchive"`
	Driftnet        string `yaml:"driftnet"`
	Fofa            string `yaml:"fofa"`
	FullHunt        string `yaml:"fullhunt"`
	GitLab          string `yaml:"gitlab"`
	Hunter          string `yaml:"hunter"`
	JSMon           string `yaml:"jsmon"`
	Netlas          string `yaml:"netlas"`
	PugRecon        string `yaml:"pugrecon"`
	Quake           string `yaml:"quake"`
	RedHuntLabs     string `yaml:"redhuntlabs"`
	Robtex          string `yaml:"robtex"`
	RSECloud        string `yaml:"rsecloud"`
	SubdomainCenter string `yaml:"subdomaincenter"`
	ThreatBook      string `yaml:"threatbook"`
	URLScan         string `yaml:"urlscan"`
	WhoisXMLAPI     string `yaml:"whoisxmlapi"`
	Windvane        string `yaml:"windvane"`
	ZoomEyeAPI      string `yaml:"zoomeyeapi"`
}

type DefaultSettings struct {
	Timeout int `yaml:"timeout"`
}

type ActiveEnumeration struct {
	Enabled      bool   `yaml:"enabled"`
	DsieveTop    int    `yaml:"dsieve_top"`
	DsieveFactor int    `yaml:"dsieve_factor"`
	OutputDir    string `yaml:"output_dir"`
}

type Database struct {
	Enabled  bool   `yaml:"enabled"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}

type LLMEnumeration struct {
	Enabled         bool    `yaml:"enabled"`
	Device          string  `yaml:"device"`
	NumPredictions  int     `yaml:"num_predictions"`
	MaxRecursion    int     `yaml:"max_recursion"`
	MaxTokens       int     `yaml:"max_tokens"`
	Temperature     float32 `yaml:"temperature"`
	RunAfterPassive bool    `yaml:"run_after_passive"`
	RunAfterActive  bool    `yaml:"run_after_active"`
}

type Manager struct {
	config     *Config
	configPath string
}

func NewManager(configPath string) *Manager {
	return &Manager{
		configPath: configPath,
	}
}

func (m *Manager) LoadConfig() error {
	if m.configPath == "" {
		m.configPath = m.findConfigFile()
	}

	if DebugLog != nil {
		DebugLog("loading provider config from %s", m.configPath)
	}

	if _, err := os.Stat(m.configPath); os.IsNotExist(err) {
		return fmt.Errorf("config file not found at %s. Please create one based on config.yaml.example", m.configPath)
	}

	data, err := os.ReadFile(m.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := m.validateConfig(&config); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	if DebugLog != nil {
		m.logFoundAPIKeys(&config.APIKeys)
	}

	m.config = &config
	return nil
}

func (m *Manager) logFoundAPIKeys(apiKeys *APIKeys) {
	v := reflect.ValueOf(*apiKeys)
	t := reflect.TypeOf(*apiKeys)

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		yamlTag := fieldType.Tag.Get("yaml")
		if yamlTag == "" {
			yamlTag = strings.ToLower(fieldType.Name)
		}

		if field.Kind() == reflect.String && field.String() != "" {
			DebugLog("api key(s) found for %s.", yamlTag)
		}
	}
}

func (m *Manager) GetConfig() *Config {
	return m.config
}

func (m *Manager) findConfigFile() string {
	if _, err := os.Stat("config.yaml"); err == nil {
		return "config.yaml"
	}

	if _, err := os.Stat("config/config.yaml"); err == nil {
		return "config/config.yaml"
	}

	if homeDir, err := os.UserHomeDir(); err == nil {
		configPath := filepath.Join(homeDir, ".samoscout", "config.yaml")
		if _, err := os.Stat(configPath); err == nil {
			return configPath
		}
	}

	return "config/config.yaml"
}

func (m *Manager) validateConfig(config *Config) error {
	if config.DefaultSettings.Timeout <= 0 {
		return fmt.Errorf("timeout must be greater than 0")
	}

	return nil
}

func (m *Manager) SetAPIKey(service, key string) error {
	if m.config == nil {
		return fmt.Errorf("configuration not loaded")
	}

	switch service {
	case "chaos":
		m.config.APIKeys.Chaos = key
	case "censys":
		m.config.APIKeys.Censys = key
	case "virustotal":
		m.config.APIKeys.VirusTotal = key
	case "securitytrails":
		m.config.APIKeys.SecurityTrails = key
	case "shodan":
		m.config.APIKeys.Shodan = key
	case "github":
		m.config.APIKeys.GitHub = key
	default:
		return fmt.Errorf("unknown service: %s", service)
	}

	return nil
}
