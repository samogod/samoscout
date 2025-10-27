package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"samoscout/pkg/config"
	"samoscout/pkg/database"
	"samoscout/pkg/orchestrator"
	"samoscout/pkg/session"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	configFile     string
	domain         string
	domainList     string
	outputFile     string
	jsonFormat     bool
	silent         bool
	stats          bool
	verbose        bool
	sources        string
	excludeSources string
	activeEnum     bool
	deepEnum       bool
	llmEnum        bool
	httpxProbe     bool
	wordlistPath   string
)

var Verbose bool

var rootCmd = &cobra.Command{
	Use:   "samoscout",
	Short: "all in one subdomain enumeration tool",
	Long:  `all in one llm powered, passive & active subdomain enumeration tool`,
	Run:   runScan,
}

func Execute() {
	hasSilentFlag := false
	for i, arg := range os.Args {
		if arg == "-dL" {
			os.Args[i] = "--dL"
		}
		if arg == "-silent" {
			os.Args[i] = "--silent"
			hasSilentFlag = true
		}
		if arg == "-stats" {
			os.Args[i] = "--stats"
		}
		if arg == "-sources" {
			os.Args[i] = "--sources"
		}
		if arg == "-es" {
			os.Args[i] = "--es"
		}
	}

	if !hasSilentFlag {
		printBanner()
	}

	if err := rootCmd.Execute(); err != nil {
		color.Red("Error: %v", err)
		os.Exit(1)
	}
}

func DebugLog(format string, args ...interface{}) {
	if Verbose {
		fmt.Printf("[DBG] "+format+"\n", args...)
	}
}

func setDebugLogFunctions() {
	config.DebugLog = DebugLog
	orchestrator.DebugLog = DebugLog
	session.DebugLog = DebugLog
	database.DebugLog = DebugLog
}

func init() {
	rootCmd.SetHelpTemplate(`Usage:
  {{.UseLine}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}

{{if .HasAvailableSubCommands}}Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}

{{end}}Flags:
INPUT:
   -d, -domain string      target domain to enumerate
   -dL, -list string       file containing list of domains to enumerate

SOURCE:
   -s, -sources string     comma-separated list of sources to use (e.g., 'subdomaincenter,shrewdeye')
   -es string              comma-separated list of sources to exclude (e.g., 'alienvault,zoomeyeapi')

ACTIVE ENUMERATION:
   -active                 enable active subdomain enumeration (wordlist + dsieve + mksub)
   -w, -wordlist string    custom wordlist path for active enumeration (default: six2dez wordlist)

AI PREDICTION:
   -llm                    enable AI-powered subdomain prediction

HTTP PROBING:
   -httpx                  enable HTTP/HTTPS probing on discovered subdomains

TRACK:
   -status string          filter by status (active, dead, new)
   -all                    query all domains

OUTPUT:
   -o, -output string      file to write output to
   -j, -json               write output in JSONL(ines) format
   -silent                 silent mode - no banner or extra output
   -stats                  display source statistics after scan

CONFIGURATION:
   -c, -config string      config file path (default: config/config.yaml)

OPTIMIZATION:
   -v, -verbose            enable verbose/debug output
{{if .HasAvailableSubCommands}}
Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`)

	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "config file path (default: config/config.yaml)")

	rootCmd.Flags().StringVarP(&domain, "domain", "d", "", "target domain to enumerate")
	rootCmd.Flags().StringVar(&domainList, "dL", "", "file containing list of domains to enumerate")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "file to write output to")
	rootCmd.Flags().BoolVarP(&jsonFormat, "json", "j", false, "write output in JSONL(ines) format")
	rootCmd.Flags().BoolVar(&silent, "silent", false, "silent mode - no banner or extra output")
	rootCmd.Flags().BoolVar(&stats, "stats", false, "display source statistics after scan")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose/debug output")
	rootCmd.Flags().StringVarP(&sources, "sources", "s", "", "comma-separated list of sources to run (e.g., 'subdomaincenter,shrewdeye')")
	rootCmd.Flags().StringVar(&excludeSources, "es", "", "comma-separated list of sources to exclude (e.g., 'alienvault,zoomeyeapi')")
	rootCmd.Flags().BoolVar(&activeEnum, "active", false, "enable active subdomain enumeration (wordlist + dsieve + mksub)")
	rootCmd.Flags().BoolVar(&deepEnum, "deep-enum", false, "enable deep level enumeration (dsieve + trickest wordlists)")
	rootCmd.Flags().BoolVar(&llmEnum, "llm", false, "enable AI-powered subdomain prediction")
	rootCmd.Flags().BoolVar(&httpxProbe, "httpx", false, "enable HTTP/HTTPS probing on discovered subdomains")
	rootCmd.Flags().StringVarP(&wordlistPath, "wordlist", "w", "", "custom wordlist path for active enumeration (default: six2dez wordlist)")

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(updateCmd)
}

func runScan(cmd *cobra.Command, args []string) {
	if domain == "" && domainList == "" {
		color.Red("Error: either -d (domain) or -dL (domain-list) is required")
		cmd.Help()
		os.Exit(1)
	}

	if domain != "" && domainList != "" {
		color.Red("Error: cannot use both -d and -dL flags together")
		cmd.Help()
		os.Exit(1)
	}

	Verbose = verbose

	if verbose {
		setDebugLogFunctions()
	}

	orch, err := orchestrator.NewOrchestrator(configFile)
	if err != nil {
		color.Red("Failed to initialize orchestrator: %v", err)
		os.Exit(1)
	}

	var domains []string

	if domain != "" {
		domains = append(domains, domain)
	}

	if domainList != "" {
		filedomains, err := readDomainsFromFile(domainList)
		if err != nil {
			color.Red("Failed to read domain list: %v", err)
			os.Exit(1)
		}
		domains = filedomains
	}

	allSuccess := true
	for _, targetDomain := range domains {
		DebugLog("enumerating subdomains for %s", targetDomain)

		scanOptions := orchestrator.ScanOptions{
			Domain:         targetDomain,
			JSONFormat:     jsonFormat,
			Stats:          stats,
			Sources:        sources,
			ExcludeSources: excludeSources,
			ActiveEnum:     activeEnum,
			DeepEnum:       deepEnum,
			LLMEnum:        llmEnum,
			HttpxProbe:     httpxProbe,
			WordlistPath:   wordlistPath,
		}

		result, err := orch.RunScan(scanOptions)
		if err != nil {
			color.Red("Scan failed for %s: %v", targetDomain, err)
			allSuccess = false
			continue
		}

		if err := handleOutput(result); err != nil {
			color.Red("Output error for %s: %v", targetDomain, err)
			allSuccess = false
			continue
		}

		if stats && !silent {
			displayStatistics(result)
		}

		if !result.Success {
			allSuccess = false
		}
	}

	if allSuccess {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}

func readDomainsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domains = append(domains, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	if len(domains) == 0 {
		return nil, fmt.Errorf("no valid domains found in file")
	}

	return domains, nil
}

func printBanner() {
	banner := color.CyanString(`
┌─┐┌─┐┌┬┐┌─┐┌─┐┌─┐┌─┐┬ ┬┌┬┐
└─┐├─┤││││ │└─┐│  │ ││ │ │ 
└─┘┴ ┴┴ ┴└─┘└─┘└─┘└─┘└─┘ ┴  @samogod
`)
	info := color.HiBlackString("one-for-all llm powered, passive & active subdomain enumeration tool")
	fmt.Println(banner)
	fmt.Println(info)
	fmt.Println()
}

func handleOutput(result *orchestrator.ScanResult) error {
	if outputFile == "" {
		if jsonFormat {
			displayJSONResults(result)
		} else {
			displayTXTResults(result)
		}
		return nil
	}

	if jsonFormat {
		return writeJSONFile(result, outputFile)
	} else {
		return writeTXTFile(result, outputFile)
	}
}

func displayTXTResults(result *orchestrator.ScanResult) {
	if !silent {
		color.Green("\nScan completed: Found %d subdomains for %s in %v",
			len(result.Subdomains), result.Domain, result.Duration)
		if len(result.ActiveWebServices) > 0 {
			color.Cyan("Active web services: %d hosts responding to HTTP/HTTPS",
				len(result.ActiveWebServices))
		}
	}
}

type SubdomainResult struct {
	Host   string `json:"host"`
	Input  string `json:"input"`
	Source string `json:"source"`
}

func displayJSONResults(result *orchestrator.ScanResult) {
	if !silent {
		color.Green("\nScan completed: Found %d subdomains for %s in %v",
			len(result.Subdomains), result.Domain, result.Duration)
		if len(result.ActiveWebServices) > 0 {
			color.Cyan("Active web services: %d hosts responding to HTTP/HTTPS",
				len(result.ActiveWebServices))
		}
	}
}

func writeTXTFile(result *orchestrator.ScanResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	for _, subdomain := range result.Subdomains {
		if _, err := fmt.Fprintln(file, subdomain); err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
	}

	return nil
}

func writeJSONFile(result *orchestrator.ScanResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	for _, subdomain := range result.Subdomains {
		source := "unknown"
		if result.SubdomainSources != nil {
			if s, ok := result.SubdomainSources[subdomain]; ok {
				source = s
			}
		}

		jsonResult := SubdomainResult{
			Host:   subdomain,
			Input:  result.Domain,
			Source: source,
		}

		jsonBytes, err := json.Marshal(jsonResult)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}

		if _, err := fmt.Fprintln(file, string(jsonBytes)); err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
	}

	if _, err := fmt.Fprintf(file, "\n# Found %d subdomains for %s in %v\n",
		len(result.Subdomains), result.Domain, result.Duration); err != nil {
		return fmt.Errorf("failed to write summary to file: %w", err)
	}

	return nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func displayStatistics(result *orchestrator.ScanResult) {
	fmt.Println()

	color.Green("[INF] Found %d subdomains for %s in %v",
		result.TotalSubdomains, result.Domain, result.Duration)
	fmt.Println()

	color.Cyan("[INF] Printing source statistics for %s", result.Domain)
	fmt.Println()

	fmt.Printf(" %-20s %-15s %-12s %-10s\n", "Source", "Duration", "Results", "Errors")
	color.Cyan(strings.Repeat("─", 60))

	stats := result.SourceStats
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Name < stats[j].Name
	})

	for _, stat := range stats {
		duration := fmt.Sprintf("%.0fms", stat.Duration.Seconds()*1000)
		if stat.Duration.Seconds() >= 1 {
			duration = fmt.Sprintf("%.3fs", stat.Duration.Seconds())
		}

		fmt.Printf(" %-20s %-15s %-12d %-10d\n",
			stat.Name,
			duration,
			stat.Results,
			stat.Errors,
		)
	}

	fmt.Println()
}
