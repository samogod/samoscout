package cmd

import (
	"fmt"
	"os"

	"github.com/samogod/samoscout/pkg/update"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var updateVerbose bool

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update samoscout to the latest version",
	Long: `Update samoscout to the latest version from GitHub releases.
This command will:
  - Check for the latest release on GitHub
  - Download the appropriate binary for your platform
  - Replace the current binary with the new version`,
	Example: `  samoscout update
  samoscout update -v`,
	Run: runUpdate,
}

func init() {
	updateCmd.Flags().BoolVarP(&updateVerbose, "verbose", "v", false, "enable verbose output during update")
}

func runUpdate(cmd *cobra.Command, args []string) {
	fmt.Println()

	if err := update.CheckAndUpdate("v"+Version, updateVerbose); err != nil {
		color.Red("Update failed: %v", err)
		os.Exit(1)
	}
}
