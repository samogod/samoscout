package cmd

import (
	"fmt"
	"os"
	"samoscout/pkg/orchestrator"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	trackStatus string
	trackAll    bool
)

var trackCmd = &cobra.Command{
	Use:   "track [domain]",
	Short: "Query subdomain tracking database",
	Long:  `Query subdomain tracking database for a specific domain or all domains`,
	Run:   runTrack,
}

func init() {
	trackCmd.Flags().StringVar(&trackStatus, "status", "", "filter by status (active, dead, new)")
	trackCmd.Flags().BoolVar(&trackAll, "all", false, "query all domains")
	rootCmd.AddCommand(trackCmd)
}

func runTrack(cmd *cobra.Command, args []string) {
	if !trackAll && len(args) == 0 {
		color.Red("Error: either provide a domain or use --all flag")
		cmd.Help()
		os.Exit(1)
	}

	if trackAll && len(args) > 0 {
		color.Red("Error: cannot use both domain and --all flag together")
		cmd.Help()
		os.Exit(1)
	}

	orch, err := orchestrator.NewOrchestrator(configFile)
	if err != nil {
		color.Red("Failed to initialize orchestrator: %v", err)
		os.Exit(1)
	}

	db := orch.GetDB()
	if db == nil || !db.IsEnabled() {
		color.Red("Error: Database is not enabled. Please enable it in config.yaml")
		os.Exit(1)
	}

	if trackStatus != "" {
		trackStatus = strings.ToUpper(trackStatus)
	}

	var records []struct {
		Domain    string
		Subdomain string
		Status    string
		FirstSeen string
		LastSeen  string
	}

	if trackAll {
		results, err := db.QueryAllSubdomains(trackStatus)
		if err != nil {
			color.Red("Failed to query database: %v", err)
			os.Exit(1)
		}
		for _, r := range results {
			records = append(records, struct {
				Domain    string
				Subdomain string
				Status    string
				FirstSeen string
				LastSeen  string
			}{
				Domain:    r.Domain,
				Subdomain: r.Subdomain,
				Status:    r.Status,
				FirstSeen: r.FirstSeen.Format("2006-01-02 15:04:05"),
				LastSeen:  r.LastSeen.Format("2006-01-02 15:04:05"),
			})
		}
	} else {
		domain := args[0]
		results, err := db.QuerySubdomains(domain, trackStatus)
		if err != nil {
			color.Red("Failed to query database: %v", err)
			os.Exit(1)
		}

		if len(results) == 0 {
			color.Yellow("[INF] Domain %s not found in database.", domain)
			os.Exit(0)
		}

		for _, r := range results {
			records = append(records, struct {
				Domain    string
				Subdomain string
				Status    string
				FirstSeen string
				LastSeen  string
			}{
				Domain:    r.Domain,
				Subdomain: r.Subdomain,
				Status:    r.Status,
				FirstSeen: r.FirstSeen.Format("2006-01-02 15:04:05"),
				LastSeen:  r.LastSeen.Format("2006-01-02 15:04:05"),
			})
		}
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, color.CyanString("DOMAIN\tSUBDOMAIN\tSTATUS\tFIRST_SEEN\tLAST_SEEN"))
	fmt.Fprintln(w, strings.Repeat("-", 100))

	for _, r := range records {
		statusColor := color.GreenString
		if r.Status == "DEAD" {
			statusColor = color.RedString
		} else if r.Status == "NEW" {
			statusColor = color.YellowString
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			r.Domain,
			r.Subdomain,
			statusColor(r.Status),
			r.FirstSeen,
			r.LastSeen,
		)
	}
	w.Flush()

	color.Green("\nTotal records: %d", len(records))
}
