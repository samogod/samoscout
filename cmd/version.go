package cmd

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const (
	Version   = "1.0.0"
	BuildDate = "2025-10-30"
	Author    = "samogod"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Long:  "Display version, build date, and author information for samoscout",
	Run: func(cmd *cobra.Command, args []string) {
		printVersionInfo()
	},
}

func printVersionInfo() {
	color.Green("Current Version:    %s", Version)
	fmt.Println()
}
