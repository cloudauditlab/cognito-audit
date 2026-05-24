package cmd

import (
	"fmt"
	"os"

	"github.com/cloudauditlab/cognito-audit/internal/audit"
	"github.com/cloudauditlab/cognito-audit/internal/report"
	"github.com/spf13/cobra"
)

var (
	poolsRegion  string
	poolsProfile string
	poolsFormat  string
)

var poolsCmd = &cobra.Command{
	Use:   "pools",
	Short: "List all Cognito User Pools in a region",
	Long: `List all Cognito User Pools in the specified AWS region.

Examples:
  cognito-audit pools
  cognito-audit pools --region us-east-1
  cognito-audit pools --format json`,
	RunE: runPools,
}

func init() {
	poolsCmd.Flags().StringVar(&poolsRegion, "region", "ap-northeast-1", "AWS region")
	poolsCmd.Flags().StringVar(&poolsProfile, "profile", "", "AWS credential profile")
	poolsCmd.Flags().StringVar(&poolsFormat, "format", "text", "Output format: text | json | csv")
}

func runPools(cmd *cobra.Command, _ []string) error {
	pools, err := audit.ListPools(cmd.Context(), poolsRegion, poolsProfile)
	if err != nil {
		return fmt.Errorf("list pools: %w", err)
	}

	if len(pools) == 0 {
		fmt.Fprintf(os.Stderr, "No User Pools found in region %s\n", poolsRegion)
		return nil
	}

	return report.WritePools(os.Stdout, pools, poolsFormat)
}
