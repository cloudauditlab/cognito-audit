package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "cognito-audit",
	Short: "AWS Cognito User Pool access auditing tool",
	Long: `cognito-audit scans Cognito User Pools and reports users by risk level.

Designed for SOC2 CC6.2/CC6.3 and ISMS A.8.2 access review compliance.

Required IAM permissions (read-only):
  cognito-idp:ListUserPools
  cognito-idp:DescribeUserPool
  cognito-idp:ListUsers
  cognito-idp:ListGroups
  cognito-idp:ListUsersInGroup`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(poolsCmd)
}
