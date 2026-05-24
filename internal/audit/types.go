package audit

import "time"

// RiskLevel represents the severity of a user's access risk flags.
type RiskLevel string

const (
	RiskOK     RiskLevel = "OK"
	RiskMedium RiskLevel = "MEDIUM"
	RiskHigh   RiskLevel = "HIGH"
)

func riskScore(r RiskLevel) int {
	switch r {
	case RiskHigh:
		return 2
	case RiskMedium:
		return 1
	default:
		return 0
	}
}

func maxRisk(a, b RiskLevel) RiskLevel {
	if riskScore(b) > riskScore(a) {
		return b
	}
	return a
}

// UserRecord holds the audited data for one Cognito user.
type UserRecord struct {
	Username       string    `json:"username"`
	Email          string    `json:"email"`
	Name           string    `json:"name,omitempty"`
	Status         string    `json:"status"`
	Enabled        bool      `json:"enabled"`
	Groups         []string  `json:"groups"`
	CreatedAt      time.Time `json:"created_at"`
	LastModifiedAt time.Time `json:"last_modified_at"`
	AccountAgeDays int       `json:"account_age_days"`
	RiskLevel      RiskLevel `json:"risk_level"`
	Flags          []string  `json:"flags"`
}

// PoolInfo holds metadata about the scanned User Pool.
type PoolInfo struct {
	PoolID     string `json:"pool_id"`
	PoolName   string `json:"pool_name"`
	Region     string `json:"region"`
	MFAConfig  string `json:"mfa_config"`
	TotalUsers int    `json:"total_users"`
}

// PoolSummaryItem is used by the `pools` command.
type PoolSummaryItem struct {
	PoolID    string `json:"pool_id"`
	PoolName  string `json:"pool_name"`
	MFAConfig string `json:"mfa_config"`
}

// Report is the top-level output of a scan.
type Report struct {
	Pool      PoolInfo     `json:"pool"`
	ScannedAt time.Time    `json:"scanned_at"`
	Users     []UserRecord `json:"users"`
	Summary   Summary      `json:"summary"`
}

// Summary aggregates risk counts.
type Summary struct {
	Total      int `json:"total"`
	HighRisk   int `json:"high_risk"`
	MediumRisk int `json:"medium_risk"`
	OK         int `json:"ok"`
}
