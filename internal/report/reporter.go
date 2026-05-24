package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/cloudauditlab/cognito-audit/internal/audit"
)

// Write writes the report in the requested format to w.
func Write(w io.Writer, r *audit.Report, format string) error {
	switch format {
	case "json":
		return writeJSON(w, r)
	case "csv":
		return writeCSV(w, r)
	default:
		return writeText(w, r)
	}
}

// WritePools writes the pool list in the requested format to w.
func WritePools(w io.Writer, pools []audit.PoolSummaryItem, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(pools)
	case "csv":
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"pool_id", "pool_name", "mfa_config"})
		for _, p := range pools {
			_ = cw.Write([]string{p.PoolID, p.PoolName, p.MFAConfig})
		}
		cw.Flush()
		return cw.Error()
	default:
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "POOL ID\tPOOL NAME\tMFA CONFIG")
		fmt.Fprintln(tw, "───────────────────────────\t──────────────────────\t──────────")
		for _, p := range pools {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", p.PoolID, p.PoolName, p.MFAConfig)
		}
		return tw.Flush()
	}
}

// ---- text -------------------------------------------------------------------

func writeText(w io.Writer, r *audit.Report) error {
	sep := strings.Repeat("─", 100)

	fmt.Fprintf(w, "\n=== Cognito User Pool Audit Report ===\n\n")
	fmt.Fprintf(w, "  Pool ID    : %s\n", r.Pool.PoolID)
	fmt.Fprintf(w, "  Pool Name  : %s\n", r.Pool.PoolName)
	fmt.Fprintf(w, "  Region     : %s\n", r.Pool.Region)
	fmt.Fprintf(w, "  MFA Config : %s\n", mfaBadge(r.Pool.MFAConfig))
	fmt.Fprintf(w, "  Total Users: %d\n", r.Pool.TotalUsers)
	fmt.Fprintf(w, "  Scanned At : %s\n", r.ScannedAt.Local().Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintln(w)

	fmt.Fprintf(w, "Risk Summary\n")
	fmt.Fprintf(w, "  [HIGH]   %d\n", r.Summary.HighRisk)
	fmt.Fprintf(w, "  [MEDIUM] %d\n", r.Summary.MediumRisk)
	fmt.Fprintf(w, "  [OK]     %d\n", r.Summary.OK)
	fmt.Fprintln(w)

	fmt.Fprintln(w, sep)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "RISK\tUSERNAME\tEMAIL\tSTATUS\tON\tAGE\tGROUPS\tFLAGS")
	fmt.Fprintln(tw, "────\t────────\t─────\t──────\t──\t───\t──────\t─────")

	for _, u := range r.Users {
		enabled := "Y"
		if !u.Enabled {
			enabled = "N"
		}
		groups := "-"
		if len(u.Groups) > 0 {
			groups = strings.Join(u.Groups, ",")
		}
		flags := "-"
		if len(u.Flags) > 0 {
			flags = strings.Join(u.Flags, " | ")
		}
		email := u.Email
		if email == "" {
			email = "-"
		}
		age := fmt.Sprintf("%dd", u.AccountAgeDays)

		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			riskLabel(u.RiskLevel),
			truncate(u.Username, 30),
			truncate(email, 35),
			u.Status,
			enabled,
			age,
			truncate(groups, 20),
			flags,
		)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	fmt.Fprintln(w, sep)
	fmt.Fprintln(w)

	if r.Summary.HighRisk > 0 || r.Summary.MediumRisk > 0 {
		fmt.Fprintln(w, "Flag Legend:")
		fmt.Fprintln(w, "  COMPROMISED         - Account marked compromised by Cognito")
		fmt.Fprintln(w, "  UNCONFIRMED_Nd      - Signup never completed, N days old")
		fmt.Fprintln(w, "  FORCE_CHANGE_PASSWORD - Temporary password never changed")
		fmt.Fprintln(w, "  DISABLED            - Account disabled but still in pool")
		fmt.Fprintln(w, "  STALE_Nd            - No attribute change in N days (*not* last-login)")
		fmt.Fprintln(w, "  PRIVILEGED:<group>  - Member of a privileged group")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "NOTE: STALE uses UserLastModifiedDate as a staleness proxy.")
		fmt.Fprintln(w, "      For actual last-login, enable CloudTrail and query InitiateAuth events.")
	}
	fmt.Fprintln(w)
	return nil
}

// ---- json -------------------------------------------------------------------

func writeJSON(w io.Writer, r *audit.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// ---- csv --------------------------------------------------------------------

func writeCSV(w io.Writer, r *audit.Report) error {
	cw := csv.NewWriter(w)

	header := []string{
		"risk_level", "username", "email", "name",
		"status", "enabled", "groups",
		"created_at", "last_modified_at", "account_age_days",
		"flags",
	}
	if err := cw.Write(header); err != nil {
		return err
	}

	for _, u := range r.Users {
		row := []string{
			string(u.RiskLevel),
			u.Username,
			u.Email,
			u.Name,
			u.Status,
			boolStr(u.Enabled),
			strings.Join(u.Groups, "|"),
			u.CreatedAt.UTC().Format(time.RFC3339),
			u.LastModifiedAt.UTC().Format(time.RFC3339),
			fmt.Sprintf("%d", u.AccountAgeDays),
			strings.Join(u.Flags, "|"),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// ---- helpers ----------------------------------------------------------------

func riskLabel(r audit.RiskLevel) string {
	switch r {
	case audit.RiskHigh:
		return "[HIGH]  "
	case audit.RiskMedium:
		return "[MEDIUM]"
	default:
		return "[OK]    "
	}
}

func mfaBadge(mfa string) string {
	switch mfa {
	case "ON":
		return "ON  (required for all users)"
	case "OPTIONAL":
		return "OPTIONAL  (users may not have MFA)"
	case "OFF":
		return "OFF  (no MFA)"
	default:
		return mfa
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
