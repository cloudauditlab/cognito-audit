package cmd

import (
	"fmt"
	"os"

	"github.com/cloudauditlab/cognito-audit/internal/audit"
	"github.com/cloudauditlab/cognito-audit/internal/report"
	"github.com/spf13/cobra"
)

var (
	poolID       string
	region       string
	profile      string
	format       string
	outputFile   string
	inactiveDays int
	flagsOnly    bool
	groupFilter  string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a Cognito User Pool and report user risk",
	Long: `Scan all users in a Cognito User Pool and classify them by risk level.

Risk levels:
  HIGH   - COMPROMISED, UNCONFIRMED (>7d), or member of a privileged group
  MEDIUM - FORCE_CHANGE_PASSWORD, DISABLED, or STALE (no modification in N days)
  OK     - CONFIRMED and Enabled

Examples:
  cognito-audit scan --pool-id ap-northeast-1_XXXXXXXX
  cognito-audit scan --pool-id ap-northeast-1_XXXXXXXX --format json > report.json
  cognito-audit scan --pool-id ap-northeast-1_XXXXXXXX --format csv  > report.csv
  cognito-audit scan --pool-id ap-northeast-1_XXXXXXXX --flags-only
  cognito-audit scan --pool-id ap-northeast-1_XXXXXXXX --group-filter admins
  cognito-audit scan --pool-id ap-northeast-1_XXXXXXXX --inactive-days 60`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVar(&poolID, "pool-id", "", "Cognito User Pool ID (required)")
	scanCmd.Flags().StringVar(&region, "region", "ap-northeast-1", "AWS region")
	scanCmd.Flags().StringVar(&profile, "profile", "", "AWS credential profile (~/.aws/credentials)")
	scanCmd.Flags().StringVar(&format, "format", "text", "Output format: text | json | csv")
	scanCmd.Flags().StringVar(&outputFile, "output", "", "Write output to file instead of stdout")
	scanCmd.Flags().IntVar(&inactiveDays, "inactive-days", 90, "Flag CONFIRMED users with no attribute change for N days")
	scanCmd.Flags().BoolVar(&flagsOnly, "flags-only", false, "Show only users with at least one flag")
	scanCmd.Flags().StringVar(&groupFilter, "group-filter", "", "Show only users in this group")
	_ = scanCmd.MarkFlagRequired("pool-id")
}

func runScan(cmd *cobra.Command, _ []string) error {
	opts := audit.Options{
		PoolID:       poolID,
		Region:       region,
		Profile:      profile,
		InactiveDays: inactiveDays,
		GroupFilter:  groupFilter,
		FlagsOnly:    flagsOnly,
	}

	r, err := audit.Run(cmd.Context(), opts)
	if err != nil {
		return fmt.Errorf("audit failed: %w", err)
	}

	out := os.Stdout
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		out = f
	}

	if err := report.Write(out, r, format); err != nil {
		return fmt.Errorf("write report: %w", err)
	}

	// Exit code 1 when HIGH risk users exist, so CI pipelines can detect issues.
	if r.Summary.HighRisk > 0 {
		os.Exit(1)
	}
	return nil
}
