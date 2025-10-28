package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/samogod/samoscout/pkg/active"
	"github.com/samogod/samoscout/pkg/config"
	"github.com/samogod/samoscout/pkg/database"
	"github.com/samogod/samoscout/pkg/llm"
	"github.com/samogod/samoscout/pkg/session"
	"github.com/samogod/samoscout/pkg/sources"

	"github.com/sirupsen/logrus"
)

var DebugLog func(string, ...interface{})

func belongsToTargetDomain(hostname, targetDomain string) bool {
	hostname = strings.TrimSpace(strings.ToLower(hostname))
	targetDomain = strings.TrimSpace(strings.ToLower(targetDomain))

	if hostname == targetDomain {
		return true
	}

	return strings.HasSuffix(hostname, "."+targetDomain)
}

type Orchestrator struct {
	config        *config.Config
	configManager *config.Manager
	logger        *logrus.Logger
	db            *database.DB
}

type Engine struct {
	Sources []sources.Source
	Session *session.Session
	Logger  *logrus.Logger
}

type ScanOptions struct {
	Domain         string
	JSONFormat     bool
	Stats          bool
	Sources        string
	ExcludeSources string
	ActiveEnum     bool
	DeepEnum       bool
	LLMEnum        bool
	HttpxProbe     bool
	WordlistPath   string
}

type SourceStat struct {
	Name     string
	Duration time.Duration
	Results  int
	Errors   int
	Skipped  bool
}

type ScanResult struct {
	Domain            string
	StartTime         time.Time
	EndTime           time.Time
	Duration          time.Duration
	TotalSubdomains   int
	Success           bool
	Errors            []error
	Subdomains        []string
	SubdomainSources  map[string]string
	SourceStats       []SourceStat
	ActiveWebServices []string
}

type customFormatter struct{}

func (f *customFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var levelText string
	switch entry.Level {
	case logrus.InfoLevel:
		levelText = "[INF]"
	case logrus.WarnLevel:
		levelText = "[WARN]"
	case logrus.ErrorLevel:
		levelText = "[ERR]"
	case logrus.DebugLevel:
		levelText = "[DBG]"
	default:
		levelText = "[???]"
	}
	return []byte(fmt.Sprintf("%s %s\n", levelText, entry.Message)), nil
}

func NewOrchestrator(configPath string) (*Orchestrator, error) {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	logger.SetFormatter(&customFormatter{})

	configManager := config.NewManager(configPath)
	if err := configManager.LoadConfig(); err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	cfg := configManager.GetConfig()

	db, err := database.New(&cfg.Database)
	if err != nil {
		logger.Warnf("Database initialization failed: %v", err)
	}

	return &Orchestrator{
		config:        cfg,
		configManager: configManager,
		logger:        logger,
		db:            db,
	}, nil
}

func NewEngine(s *session.Session, logger *logrus.Logger, selectedSources string, excludedSources string) *Engine {
	allSources := []string{
		"crtsh", "alienvault", "anubis", "abuseipdb", "cebaidu", "commoncrawl", "digicert",
		"digitorus", "dnsgrep", "hackertarget", "hudsonrock", "myssl", "netcraft",
		"racent", "rapiddns", "reconcloud", "shrewdeye", "sitedossier", "subdomaincenter", "threatcrowd",
		"threatminer", "waybackarchive",
		"virustotal", "bevigil", "bufferover", "builtwith", "c99", "censys",
		"certspotter", "chaos", "chinaz", "digitalyama", "dnsdb", "dnsdumpster",
		"dnsrepo", "driftnet", "fofa", "fullhunt", "gitlab", "hunter",
		"jsmon", "netlas", "pugrecon", "quake", "redhuntlabs", "robtex",
		"rsecloud", "securitytrails", "shodan", "threatbook", "urlscan",
		"whoisxmlapi", "windvane", "zoomeyeapi", "cloudflare",
	}

	if selectedSources != "" && excludedSources != "" {
		logger.Warn("Both -s (sources) and --exclude-sources flags specified. Using -s (sources) and ignoring exclusions.")
		excludedSources = ""
	}

	excludedSourcesMap := make(map[string]bool)
	if excludedSources != "" {
		excludedList := strings.Split(excludedSources, ",")
		for _, sourceName := range excludedList {
			sourceName = strings.TrimSpace(strings.ToLower(sourceName))
			excludedSourcesMap[sourceName] = true
		}
	}

	enabledSources := make(map[string]bool)
	if selectedSources != "" {
		requestedSources := strings.Split(selectedSources, ",")
		for _, sourceName := range requestedSources {
			sourceName = strings.TrimSpace(strings.ToLower(sourceName))
			validSource := false
			for _, validName := range allSources {
				if sourceName == validName {
					validSource = true
					break
				}
			}
			if validSource {
				enabledSources[sourceName] = true
			} else {
				logger.Warnf("Unknown source: %s", sourceName)
			}
		}
		if len(enabledSources) == 0 {
			logger.Warn("No valid sources specified, using all sources")
			for _, source := range allSources {
				enabledSources[source] = true
			}
		}
	} else if excludedSources != "" {
		for _, source := range allSources {
			if !excludedSourcesMap[source] {
				enabledSources[source] = true
			}
		}
		if len(enabledSources) == 0 {
			logger.Warn("All sources excluded, using all sources instead")
			for _, source := range allSources {
				enabledSources[source] = true
			}
		}
	} else {
		for _, source := range allSources {
			enabledSources[source] = true
		}
	}

	sourceList := []sources.Source{}

	if enabledSources["crtsh"] {
		sourceList = append(sourceList, &sources.Crtsh{})
	}
	if enabledSources["alienvault"] {
		sourceList = append(sourceList, &sources.AlienVault{})
	}
	if enabledSources["anubis"] {
		sourceList = append(sourceList, &sources.Anubis{})
	}
	if enabledSources["abuseipdb"] {
		sourceList = append(sourceList, &sources.AbuseIPDB{})
	}
	if enabledSources["cebaidu"] {
		sourceList = append(sourceList, &sources.Cebaidu{})
	}
	if enabledSources["commoncrawl"] {
		sourceList = append(sourceList, &sources.CommonCrawl{})
	}
	if enabledSources["digicert"] {
		sourceList = append(sourceList, &sources.DigiCert{})
	}
	if enabledSources["digitorus"] {
		sourceList = append(sourceList, &sources.Digitorus{})
	}
	if enabledSources["dnsgrep"] {
		sourceList = append(sourceList, &sources.Dnsgrep{})
	}
	if enabledSources["hackertarget"] {
		sourceList = append(sourceList, &sources.HackerTarget{})
	}
	if enabledSources["hudsonrock"] {
		sourceList = append(sourceList, &sources.HudsonRock{})
	}
	if enabledSources["myssl"] {
		sourceList = append(sourceList, &sources.MySSL{})
	}
	if enabledSources["netcraft"] {
		sourceList = append(sourceList, &sources.Netcraft{})
	}
	if enabledSources["racent"] {
		sourceList = append(sourceList, &sources.Racent{})
	}
	if enabledSources["rapiddns"] {
		sourceList = append(sourceList, &sources.RapidDNS{})
	}
	if enabledSources["reconcloud"] {
		sourceList = append(sourceList, &sources.ReconCloud{})
	}
	if enabledSources["shrewdeye"] {
		sourceList = append(sourceList, &sources.ShrewdEye{})
	}
	if enabledSources["sitedossier"] {
		sourceList = append(sourceList, &sources.SiteDossier{})
	}
	if enabledSources["subdomaincenter"] {
		sourceList = append(sourceList, &sources.SubdomainCenter{})
	}
	if enabledSources["threatcrowd"] {
		sourceList = append(sourceList, &sources.ThreatCrowd{})
	}
	if enabledSources["threatminer"] {
		sourceList = append(sourceList, &sources.ThreatMiner{})
	}
	if enabledSources["waybackarchive"] {
		sourceList = append(sourceList, &sources.WaybackArchive{})
	}

	enabledSourceNames := make([]string, 0, len(allSources))

	if s.Keys.VirusTotal != "" && (selectedSources == "" || enabledSources["virustotal"]) {
		sourceList = append(sourceList, &sources.VirusTotal{})
		enabledSourceNames = append(enabledSourceNames, "virustotal")
	}

	if s.Keys.BeVigil != "" && (selectedSources == "" || enabledSources["bevigil"]) {
		sourceList = append(sourceList, &sources.BeVigil{})
		enabledSourceNames = append(enabledSourceNames, "bevigil")
	}

	if s.Keys.BufferOver != "" && (selectedSources == "" || enabledSources["bufferover"]) {
		sourceList = append(sourceList, &sources.BufferOver{})
		enabledSourceNames = append(enabledSourceNames, "bufferover")
	}

	if s.Keys.BuiltWith != "" && (selectedSources == "" || enabledSources["builtwith"]) {
		sourceList = append(sourceList, &sources.BuiltWith{})
		enabledSourceNames = append(enabledSourceNames, "builtwith")
	}

	if s.Keys.C99 != "" && (selectedSources == "" || enabledSources["c99"]) {
		sourceList = append(sourceList, &sources.C99{})
		enabledSourceNames = append(enabledSourceNames, "c99")
	}

	if s.Keys.Censys != "" && (selectedSources == "" || enabledSources["censys"]) {
		sourceList = append(sourceList, &sources.Censys{})
		enabledSourceNames = append(enabledSourceNames, "censys")
	}

	if s.Keys.CertSpotter != "" && (selectedSources == "" || enabledSources["certspotter"]) {
		sourceList = append(sourceList, &sources.CertSpotter{})
		enabledSourceNames = append(enabledSourceNames, "certspotter")
	}

	if s.Keys.Chaos != "" && (selectedSources == "" || enabledSources["chaos"]) {
		sourceList = append(sourceList, &sources.Chaos{})
		enabledSourceNames = append(enabledSourceNames, "chaos")
	}

	if s.Keys.Chinaz != "" && (selectedSources == "" || enabledSources["chinaz"]) {
		sourceList = append(sourceList, &sources.Chinaz{})
		enabledSourceNames = append(enabledSourceNames, "chinaz")
	}

	if s.Keys.DigitalYama != "" && (selectedSources == "" || enabledSources["digitalyama"]) {
		sourceList = append(sourceList, &sources.DigitalYama{})
		enabledSourceNames = append(enabledSourceNames, "digitalyama")
	}

	if s.Keys.DNSDB != "" && (selectedSources == "" || enabledSources["dnsdb"]) {
		sourceList = append(sourceList, &sources.DNSDB{})
		enabledSourceNames = append(enabledSourceNames, "dnsdb")
	}

	if s.Keys.DNSDumpster != "" && (selectedSources == "" || enabledSources["dnsdumpster"]) {
		sourceList = append(sourceList, &sources.DNSDumpster{})
		enabledSourceNames = append(enabledSourceNames, "dnsdumpster")
	}

	if s.Keys.DNSRepo != "" && (selectedSources == "" || enabledSources["dnsrepo"]) {
		sourceList = append(sourceList, &sources.DNSRepo{})
		enabledSourceNames = append(enabledSourceNames, "dnsrepo")
	}

	if s.Keys.Driftnet != "" && (selectedSources == "" || enabledSources["driftnet"]) {
		sourceList = append(sourceList, &sources.Driftnet{})
		enabledSourceNames = append(enabledSourceNames, "driftnet")
	}

	if s.Keys.Fofa != "" && (selectedSources == "" || enabledSources["fofa"]) {
		sourceList = append(sourceList, &sources.Fofa{})
		enabledSourceNames = append(enabledSourceNames, "fofa")
	}

	if s.Keys.FullHunt != "" && (selectedSources == "" || enabledSources["fullhunt"]) {
		sourceList = append(sourceList, &sources.FullHunt{})
		enabledSourceNames = append(enabledSourceNames, "fullhunt")
	}

	if s.Keys.GitLab != "" && (selectedSources == "" || enabledSources["gitlab"]) {
		sourceList = append(sourceList, &sources.GitLab{})
		enabledSourceNames = append(enabledSourceNames, "gitlab")
	}

	if s.Keys.Hunter != "" && (selectedSources == "" || enabledSources["hunter"]) {
		sourceList = append(sourceList, &sources.Hunter{})
		enabledSourceNames = append(enabledSourceNames, "hunter")
	}

	if s.Keys.JSMon != "" && (selectedSources == "" || enabledSources["jsmon"]) {
		sourceList = append(sourceList, &sources.JSMon{})
		enabledSourceNames = append(enabledSourceNames, "jsmon")
	}

	if s.Keys.Netlas != "" && (selectedSources == "" || enabledSources["netlas"]) {
		sourceList = append(sourceList, &sources.Netlas{})
		enabledSourceNames = append(enabledSourceNames, "netlas")
	}

	if s.Keys.PugRecon != "" && (selectedSources == "" || enabledSources["pugrecon"]) {
		sourceList = append(sourceList, &sources.PugRecon{})
		enabledSourceNames = append(enabledSourceNames, "pugrecon")
	}

	if s.Keys.Quake != "" && (selectedSources == "" || enabledSources["quake"]) {
		sourceList = append(sourceList, &sources.Quake{})
		enabledSourceNames = append(enabledSourceNames, "quake")
	}

	if s.Keys.RedHuntLabs != "" && (selectedSources == "" || enabledSources["redhuntlabs"]) {
		sourceList = append(sourceList, &sources.RedHuntLabs{})
		enabledSourceNames = append(enabledSourceNames, "redhuntlabs")
	}

	if s.Keys.Robtex != "" && (selectedSources == "" || enabledSources["robtex"]) {
		sourceList = append(sourceList, &sources.Robtex{})
		enabledSourceNames = append(enabledSourceNames, "robtex")
	}

	if s.Keys.RSECloud != "" && (selectedSources == "" || enabledSources["rsecloud"]) {
		sourceList = append(sourceList, &sources.RSECloud{})
		enabledSourceNames = append(enabledSourceNames, "rsecloud")
	}

	if s.Keys.SecurityTrails != "" && (selectedSources == "" || enabledSources["securitytrails"]) {
		sourceList = append(sourceList, &sources.SecurityTrails{})
		enabledSourceNames = append(enabledSourceNames, "securitytrails")
	}

	if s.Keys.Shodan != "" && (selectedSources == "" || enabledSources["shodan"]) {
		sourceList = append(sourceList, &sources.Shodan{})
		enabledSourceNames = append(enabledSourceNames, "shodan")
	}

	if s.Keys.ThreatBook != "" && (selectedSources == "" || enabledSources["threatbook"]) {
		sourceList = append(sourceList, &sources.ThreatBook{})
		enabledSourceNames = append(enabledSourceNames, "threatbook")
	}

	if s.Keys.URLScan != "" && (selectedSources == "" || enabledSources["urlscan"]) {
		sourceList = append(sourceList, &sources.URLScan{})
		enabledSourceNames = append(enabledSourceNames, "urlscan")
	}

	if s.Keys.WhoisXMLAPI != "" && (selectedSources == "" || enabledSources["whoisxmlapi"]) {
		sourceList = append(sourceList, &sources.WhoisXMLAPI{})
		enabledSourceNames = append(enabledSourceNames, "whoisxmlapi")
	}

	if s.Keys.Windvane != "" && (selectedSources == "" || enabledSources["windvane"]) {
		sourceList = append(sourceList, &sources.Windvane{})
		enabledSourceNames = append(enabledSourceNames, "windvane")
	}

	if s.Keys.ZoomEyeAPI != "" && (selectedSources == "" || enabledSources["zoomeyeapi"]) {
		sourceList = append(sourceList, &sources.ZoomEyeAPI{})
		enabledSourceNames = append(enabledSourceNames, "zoomeyeapi")
	}

	if s.Keys.Cloudflare != "" && (selectedSources == "" || enabledSources["cloudflare"]) {
		sourceList = append(sourceList, &sources.Cloudflare{})
		enabledSourceNames = append(enabledSourceNames, "cloudflare")
	}

	if selectedSources != "" {
		logger.Infof("Running with selected sources: %d enabled", len(sourceList))
		if len(sourceList) > 0 {
			sourceNames := make([]string, 0, len(sourceList))
			for _, source := range sourceList {
				sourceNames = append(sourceNames, source.Name())
			}
			logger.Infof("Enabled sources: %s", strings.Join(sourceNames, ", "))
		}
	} else if excludedSources != "" {
		logger.Infof("Running with %d sources (excluded: %s)", len(sourceList), excludedSources)
	} else {
		logger.Infof("Running with all available sources: %d enabled", len(sourceList))
		logger.Infof("Multi-stage permutation engine with dsieve, mksub, gotator")
		logger.Infof("GPT transformer inference with iterative beam search")
	}

	return &Engine{
		Sources: sourceList,
		Session: s,
		Logger:  logger,
	}
}

type EnumerationResult struct {
	Result sources.Result
	Stats  map[string]*SourceStat
}

func (e *Engine) RunPassiveEnumeration(ctx context.Context, domain string, collectStats bool) <-chan EnumerationResult {
	results := make(chan EnumerationResult)
	wg := &sync.WaitGroup{}

	stats := make(map[string]*SourceStat)
	statsMutex := &sync.Mutex{}

	for _, source := range e.Sources {
		wg.Add(1)
		go func(s sources.Source) {
			defer wg.Done()

			sourceName := s.Name()
			startTime := time.Now()
			resultCount := 0
			errorCount := 0

			agentResults := s.Run(ctx, domain, e.Session)

			for result := range agentResults {
				if result.Error != nil {
					errorCount++
					continue
				}
				resultCount++

				select {
				case results <- EnumerationResult{Result: result, Stats: nil}:
				case <-ctx.Done():
					return
				}
			}

			if collectStats {
				duration := time.Since(startTime)
				statsMutex.Lock()
				stats[sourceName] = &SourceStat{
					Name:     sourceName,
					Duration: duration,
					Results:  resultCount,
					Errors:   errorCount,
					Skipped:  false,
				}
				statsMutex.Unlock()
			}
		}(source)
	}

	go func() {
		wg.Wait()
		if collectStats {
			results <- EnumerationResult{Result: sources.Result{}, Stats: stats}
		}
		close(results)
	}()

	return results
}

func (o *Orchestrator) RunScan(options ScanOptions) (*ScanResult, error) {
	startTime := time.Now()

	result := &ScanResult{
		Domain:    options.Domain,
		StartTime: startTime,
		Success:   false,
		Errors:    []error{},
	}

	if err := o.runPassiveReconWithEngine(options.Domain, result, options.JSONFormat, options.Stats, options.Sources, options.ExcludeSources); err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("passive reconnaissance failed: %w", err))
	}

	if (options.LLMEnum || o.config.LLMEnumeration.Enabled) && o.config.LLMEnumeration.RunAfterPassive {
		if err := o.runLLMEnumeration(options.Domain, result, options.JSONFormat); err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("LLM enumeration failed: %w", err))
			o.logger.Errorf("LLM enumeration error: %v", err)
		}
	}

	if options.ActiveEnum || o.config.ActiveEnumeration.Enabled {
		if err := o.runActiveEnumeration(options.Domain, result, options.JSONFormat, options.DeepEnum, options.WordlistPath); err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("active enumeration failed: %w", err))
			o.logger.Errorf("Active enumeration error: %v", err)
		}
	}

	if (options.LLMEnum || o.config.LLMEnumeration.Enabled) && o.config.LLMEnumeration.RunAfterActive {
		if err := o.runLLMEnumeration(options.Domain, result, options.JSONFormat); err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("LLM enumeration failed: %w", err))
			o.logger.Errorf("LLM enumeration error: %v", err)
		}
	}

	endTime := time.Now()
	result.EndTime = endTime
	result.Duration = endTime.Sub(startTime)
	result.Success = len(result.Errors) == 0 || result.TotalSubdomains > 0

	if options.HttpxProbe && len(result.Subdomains) > 0 {
		if err := o.runHTTPProbing(options.Domain, result); err != nil {
			if DebugLog != nil {
				DebugLog("HTTP probing failed: %v", err)
			}
		}
	}

	if o.db != nil && o.db.IsEnabled() {
		if err := o.db.TrackSubdomains(options.Domain, result.Subdomains); err != nil {
			o.logger.Warnf("Failed to track subdomains in database: %v", err)
		}
	}

	return result, nil
}

type SubdomainResult struct {
	Host   string `json:"host"`
	Input  string `json:"input"`
	Source string `json:"source"`
}

func (o *Orchestrator) runPassiveReconWithEngine(domain string, result *ScanResult, jsonFormat bool, collectStats bool, sources string, excludeSources string) error {

	sess, err := session.New(o.config)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	engine := NewEngine(sess, o.logger, sources, excludeSources)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(o.config.DefaultSettings.Timeout)*time.Minute)
	defer cancel()

	passiveResults := engine.RunPassiveEnumeration(ctx, domain, collectStats)

	found := make(map[string]struct{})
	var allSubdomains []string
	subdomainSources := make(map[string]string)
	var sourceStats []SourceStat

	for enumResult := range passiveResults {
		if enumResult.Stats != nil {
			for _, stat := range enumResult.Stats {
				sourceStats = append(sourceStats, *stat)
			}
			continue
		}

		subdomain := enumResult.Result.Value

		if !belongsToTargetDomain(subdomain, domain) {
			continue
		}

		if _, ok := found[subdomain]; !ok {
			found[subdomain] = struct{}{}
			allSubdomains = append(allSubdomains, subdomain)
			subdomainSources[subdomain] = enumResult.Result.Source

			if DebugLog != nil {
				DebugLog("found subdomain: %s [%s]", subdomain, enumResult.Result.Source)
			}

			if jsonFormat {
				jsonResult := SubdomainResult{
					Host:   subdomain,
					Input:  domain,
					Source: enumResult.Result.Source,
				}
				jsonBytes, _ := json.Marshal(jsonResult)
				fmt.Println(string(jsonBytes))
			} else {
				fmt.Println(subdomain)
			}
		}
	}

	result.TotalSubdomains = len(allSubdomains)
	result.Subdomains = allSubdomains
	result.SubdomainSources = subdomainSources
	result.SourceStats = sourceStats

	return nil
}

func (o *Orchestrator) GetConfig() *config.Config {
	return o.config
}

func (o *Orchestrator) GetDB() *database.DB {
	return o.db
}

func (o *Orchestrator) runActiveEnumeration(domain string, result *ScanResult, jsonFormat bool, deepEnum bool, wordlistPath string) error {
	if len(result.Subdomains) == 0 {
		if DebugLog != nil {
			DebugLog("no passive subdomains found, skipping active enumeration")
		}
		return nil
	}

	if DebugLog != nil {
		DebugLog("starting active enumeration with %d passive subdomains", len(result.Subdomains))
	}

	pipelineConfig := active.PipelineConfig{
		Domain:             domain,
		PassiveSubdomains:  result.Subdomains,
		OutputDir:          o.config.ActiveEnumeration.OutputDir,
		DsieveTop:          o.config.ActiveEnumeration.DsieveTop,
		DsieveFactor:       o.config.ActiveEnumeration.DsieveFactor,
		Verbose:            DebugLog != nil,
		DeepEnum:           deepEnum,
		CustomWordlistPath: wordlistPath,
	}

	pipelineResult, err := active.RunActivePipeline(pipelineConfig)
	if err != nil {
		return fmt.Errorf("active pipeline failed: %w", err)
	}

	activeSubdomains := pipelineResult.ActiveSubdomains

	allSubdomains := active.MergeAndDeduplicate(
		result.Subdomains,
		activeSubdomains,
	)

	initialCount := len(result.Subdomains)
	result.Subdomains = allSubdomains
	result.TotalSubdomains = len(allSubdomains)

	passiveSet := make(map[string]bool)
	for _, sub := range result.Subdomains[:initialCount] {
		passiveSet[strings.ToLower(sub)] = true
	}

	for _, subdomain := range activeSubdomains {
		if !passiveSet[strings.ToLower(subdomain)] {
			if jsonFormat {
				jsonResult := SubdomainResult{
					Host:   subdomain,
					Input:  domain,
					Source: "active",
				}
				jsonBytes, _ := json.Marshal(jsonResult)
				fmt.Println(string(jsonBytes))
			} else {
				fmt.Println(subdomain)
			}
		}
	}

	if DebugLog != nil {
		DebugLog("active enumeration completed: found %d new subdomains in %v",
			pipelineResult.TotalNewSubdomains, pipelineResult.Duration)
	}

	return nil
}

func (o *Orchestrator) writeSubdomainsToFile(filePath string, subdomains []string) error {
	content := strings.Join(subdomains, "\n")
	if content != "" {
		content += "\n"
	}
	return os.WriteFile(filePath, []byte(content), 0644)
}

func (o *Orchestrator) runLLMEnumeration(
	domain string,
	result *ScanResult,
	jsonFormat bool,
) error {

	if len(result.Subdomains) == 0 {
		if DebugLog != nil {
			DebugLog("no subdomains to seed LLM, skipping")
		}
		return nil
	}

	if DebugLog != nil {
		DebugLog("starting LLM enumeration with %d seed domains", len(result.Subdomains))
	}

	domainDir := filepath.Join(o.config.ActiveEnumeration.OutputDir, domain)
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	llmConfig := &llm.Config{
		NumPredictions:    o.config.LLMEnumeration.NumPredictions,
		MaxRecursion:      o.config.LLMEnumeration.MaxRecursion,
		MaxTokens:         o.config.LLMEnumeration.MaxTokens,
		Temperature:       o.config.LLMEnumeration.Temperature,
		ResolutionThreads: 150,
		Device:            o.config.LLMEnumeration.Device,
		OutputDir:         domainDir,
		Verbose:           DebugLog != nil,
	}

	llmEngine, err := llm.New(llmConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize LLM: %w", err)
	}
	defer llmEngine.Close()

	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(o.config.DefaultSettings.Timeout)*time.Minute,
	)
	defer cancel()

	predictions, err := llmEngine.Enumerate(ctx, result.Subdomains, domain)
	if err != nil {
		return fmt.Errorf("LLM enumeration failed: %w", err)
	}

	passiveSet := make(map[string]bool)
	for _, sub := range result.Subdomains {
		passiveSet[strings.ToLower(sub)] = true
	}

	newCount := 0
	for _, pred := range predictions {
		if !passiveSet[strings.ToLower(pred)] {
			result.Subdomains = append(result.Subdomains, pred)
			result.SubdomainSources[pred] = "llm"
			newCount++

			if jsonFormat {
				jsonResult := SubdomainResult{
					Host:   pred,
					Input:  domain,
					Source: "llm",
				}
				jsonBytes, _ := json.Marshal(jsonResult)
				fmt.Println(string(jsonBytes))
			} else {
				fmt.Println(pred)
			}
		}
	}

	result.TotalSubdomains = len(result.Subdomains)

	return nil
}

func (o *Orchestrator) runHTTPProbing(domain string, result *ScanResult) error {
	if len(result.Subdomains) == 0 {
		return nil
	}

	domainDir := filepath.Join(o.config.ActiveEnumeration.OutputDir, domain)
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	subdomainsToProbe := result.Subdomains

	if len(result.ActiveWebServices) > 0 {
		if DebugLog != nil {
			DebugLog("active enumeration already probed some subdomains, checking for new ones")
		}

		alreadyProbed := make(map[string]bool)
		for _, url := range result.ActiveWebServices {
			host := strings.TrimPrefix(url, "https://")
			host = strings.TrimPrefix(host, "http://")
			host = strings.Split(host, "/")[0]
			alreadyProbed[strings.ToLower(host)] = true
		}

		var newSubdomains []string
		for _, sub := range result.Subdomains {
			if !alreadyProbed[strings.ToLower(sub)] {
				newSubdomains = append(newSubdomains, sub)
			}
		}

		if len(newSubdomains) == 0 {
			if DebugLog != nil {
				DebugLog("all subdomains already probed, skipping HTTP probing")
			}
			return nil
		}

		if DebugLog != nil {
			DebugLog("found %d new subdomains to probe", len(newSubdomains))
		}
		subdomainsToProbe = newSubdomains
	}

	if DebugLog != nil {
		DebugLog("running HTTP probing on %d subdomains", len(subdomainsToProbe))
	}

	activeURLs, err := active.ProbeHTTPSimple(subdomainsToProbe, domainDir, DebugLog != nil)
	if err != nil {
		return fmt.Errorf("HTTP probing failed: %w", err)
	}

	if len(result.ActiveWebServices) > 0 {
		result.ActiveWebServices = append(result.ActiveWebServices, activeURLs...)
	} else {
		result.ActiveWebServices = activeURLs
	}

	return nil
}
