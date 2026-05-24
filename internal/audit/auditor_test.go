package audit

import (
	"fmt"
	"testing"
	"time"
)

// ---- helpers ----------------------------------------------------------------

// newUser builds a UserRecord for testing without touching AWS.
func newUser(status string, enabled bool, ageDays int, groups []string) UserRecord {
	now := time.Now()
	created := now.AddDate(0, 0, -ageDays)
	return UserRecord{
		Username:       "testuser",
		Email:          "test@example.com",
		Status:         status,
		Enabled:        enabled,
		Groups:         groups,
		CreatedAt:      created,
		LastModifiedAt: created, // same as created for simplicity
		AccountAgeDays: ageDays,
	}
}

func hasFlag(r *UserRecord, prefix string) bool {
	for _, f := range r.Flags {
		if len(f) >= len(prefix) && f[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

func assertRisk(t *testing.T, r *UserRecord, want RiskLevel) {
	t.Helper()
	if r.RiskLevel != want {
		t.Errorf("RiskLevel = %q, want %q (flags: %v)", r.RiskLevel, want, r.Flags)
	}
}

func assertHasFlag(t *testing.T, r *UserRecord, prefix string) {
	t.Helper()
	if !hasFlag(r, prefix) {
		t.Errorf("expected flag with prefix %q, got flags: %v", prefix, r.Flags)
	}
}

func assertNoFlag(t *testing.T, r *UserRecord, prefix string) {
	t.Helper()
	if hasFlag(r, prefix) {
		t.Errorf("did not expect flag with prefix %q, got flags: %v", prefix, r.Flags)
	}
}

// ---- evaluateRisk -----------------------------------------------------------

func TestEvaluateRisk_Compromised(t *testing.T) {
	r := newUser("COMPROMISED", true, 10, nil)
	evaluateRisk(&r, 90, time.Now())

	assertRisk(t, &r, RiskHigh)
	assertHasFlag(t, &r, "COMPROMISED")
}

func TestEvaluateRisk_UnconfirmedOld(t *testing.T) {
	r := newUser("UNCONFIRMED", true, 30, nil)
	evaluateRisk(&r, 90, time.Now())

	assertRisk(t, &r, RiskHigh)
	assertHasFlag(t, &r, "UNCONFIRMED_")
}

func TestEvaluateRisk_UnconfirmedNew(t *testing.T) {
	// Within 7 days — not yet flagged
	r := newUser("UNCONFIRMED", true, 3, nil)
	evaluateRisk(&r, 90, time.Now())

	assertRisk(t, &r, RiskOK)
	assertNoFlag(t, &r, "UNCONFIRMED_")
}

func TestEvaluateRisk_PrivilegedGroup(t *testing.T) {
	cases := []struct {
		group string
	}{
		{"admins"},
		{"administrators"},
		{"admin-prod"},
		{"root"},
		{"super-users"},
		{"owner"},
		{"ops"},
		{"operator"},
	}
	for _, tc := range cases {
		t.Run(tc.group, func(t *testing.T) {
			r := newUser("CONFIRMED", true, 10, []string{tc.group})
			evaluateRisk(&r, 90, time.Now())

			assertRisk(t, &r, RiskHigh)
			assertHasFlag(t, &r, "PRIVILEGED:")
		})
	}
}

func TestEvaluateRisk_NonPrivilegedGroup(t *testing.T) {
	r := newUser("CONFIRMED", true, 10, []string{"developers", "viewers", "readonly"})
	evaluateRisk(&r, 90, time.Now())

	assertRisk(t, &r, RiskOK)
	assertNoFlag(t, &r, "PRIVILEGED:")
}

func TestEvaluateRisk_ForceChangePassword(t *testing.T) {
	r := newUser("FORCE_CHANGE_PASSWORD", true, 10, nil)
	evaluateRisk(&r, 90, time.Now())

	assertRisk(t, &r, RiskMedium)
	assertHasFlag(t, &r, "FORCE_CHANGE_PASSWORD")
}

func TestEvaluateRisk_Disabled(t *testing.T) {
	r := newUser("CONFIRMED", false, 10, nil)
	evaluateRisk(&r, 90, time.Now())

	assertRisk(t, &r, RiskMedium)
	assertHasFlag(t, &r, "DISABLED")
}

func TestEvaluateRisk_Stale(t *testing.T) {
	// LastModifiedAt = 120 days ago, threshold = 90 days
	now := time.Now()
	r := UserRecord{
		Username:       "staleuser",
		Status:         "CONFIRMED",
		Enabled:        true,
		Groups:         []string{},
		CreatedAt:      now.AddDate(0, 0, -120),
		LastModifiedAt: now.AddDate(0, 0, -120),
		AccountAgeDays: 120,
	}
	evaluateRisk(&r, 90, now)

	assertRisk(t, &r, RiskMedium)
	assertHasFlag(t, &r, "STALE_")
}

func TestEvaluateRisk_StaleNotTriggeredWhenDisabled(t *testing.T) {
	// Disabled user should not also get STALE (DISABLED is enough)
	now := time.Now()
	r := UserRecord{
		Username:       "disableduser",
		Status:         "CONFIRMED",
		Enabled:        false,
		Groups:         []string{},
		CreatedAt:      now.AddDate(0, 0, -200),
		LastModifiedAt: now.AddDate(0, 0, -200),
		AccountAgeDays: 200,
	}
	evaluateRisk(&r, 90, now)

	// DISABLED flag must exist
	assertHasFlag(t, &r, "DISABLED")
	// STALE should NOT be added (user is disabled, not just stale)
	assertNoFlag(t, &r, "STALE_")
}

func TestEvaluateRisk_RecentlyModifiedNotStale(t *testing.T) {
	now := time.Now()
	r := UserRecord{
		Username:       "activeuser",
		Status:         "CONFIRMED",
		Enabled:        true,
		Groups:         []string{},
		CreatedAt:      now.AddDate(0, 0, -200),
		LastModifiedAt: now.AddDate(0, 0, -30), // modified 30 days ago
		AccountAgeDays: 200,
	}
	evaluateRisk(&r, 90, now)

	assertRisk(t, &r, RiskOK)
	assertNoFlag(t, &r, "STALE_")
}

func TestEvaluateRisk_OK(t *testing.T) {
	r := newUser("CONFIRMED", true, 10, []string{"developers"})
	evaluateRisk(&r, 90, time.Now())

	assertRisk(t, &r, RiskOK)
	if len(r.Flags) != 0 {
		t.Errorf("expected no flags, got: %v", r.Flags)
	}
}

func TestEvaluateRisk_HighBeatsmedium(t *testing.T) {
	// A disabled user in an admin group should be HIGH, not MEDIUM
	r := newUser("CONFIRMED", false, 10, []string{"admins"})
	evaluateRisk(&r, 90, time.Now())

	assertRisk(t, &r, RiskHigh)
	assertHasFlag(t, &r, "PRIVILEGED:")
	assertHasFlag(t, &r, "DISABLED")
}

func TestEvaluateRisk_MultipleFlags(t *testing.T) {
	// FORCE_CHANGE_PASSWORD + admin group → HIGH with two flags
	r := newUser("FORCE_CHANGE_PASSWORD", true, 10, []string{"admins"})
	evaluateRisk(&r, 90, time.Now())

	assertRisk(t, &r, RiskHigh)
	assertHasFlag(t, &r, "FORCE_CHANGE_PASSWORD")
	assertHasFlag(t, &r, "PRIVILEGED:")
}

// ---- isPrivilegedGroup ------------------------------------------------------

func TestIsPrivilegedGroup(t *testing.T) {
	cases := []struct {
		name      string
		want      bool
	}{
		{"admins", true},
		{"admin", true},
		{"ADMINS", true},       // case insensitive
		{"prod-admins", true},
		{"administrators", true},
		{"root", true},
		{"superuser", true},
		{"owner", true},
		{"ops", true},
		{"operator", true},
		{"developers", false},
		{"viewers", false},
		{"readonly", false},
		{"users", false},
		{"everyone", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isPrivilegedGroup(tc.name)
			if got != tc.want {
				t.Errorf("isPrivilegedGroup(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// ---- maxRisk ----------------------------------------------------------------

func TestMaxRisk(t *testing.T) {
	cases := []struct {
		a, b RiskLevel
		want RiskLevel
	}{
		{RiskOK, RiskOK, RiskOK},
		{RiskOK, RiskMedium, RiskMedium},
		{RiskMedium, RiskOK, RiskMedium},
		{RiskMedium, RiskHigh, RiskHigh},
		{RiskHigh, RiskMedium, RiskHigh},
		{RiskHigh, RiskOK, RiskHigh},
		{RiskHigh, RiskHigh, RiskHigh},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s_vs_%s", tc.a, tc.b), func(t *testing.T) {
			got := maxRisk(tc.a, tc.b)
			if got != tc.want {
				t.Errorf("maxRisk(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// ---- buildSummary -----------------------------------------------------------

func TestBuildSummary(t *testing.T) {
	records := []UserRecord{
		{RiskLevel: RiskHigh},
		{RiskLevel: RiskHigh},
		{RiskLevel: RiskMedium},
		{RiskLevel: RiskOK},
		{RiskLevel: RiskOK},
	}

	// total = 8 (includes users filtered out by flags-only etc.)
	s := buildSummary(records, 8)

	if s.Total != 8 {
		t.Errorf("Total = %d, want 8", s.Total)
	}
	if s.HighRisk != 2 {
		t.Errorf("HighRisk = %d, want 2", s.HighRisk)
	}
	if s.MediumRisk != 1 {
		t.Errorf("MediumRisk = %d, want 1", s.MediumRisk)
	}
	if s.OK != 2 {
		t.Errorf("OK = %d, want 2", s.OK)
	}
}

func TestBuildSummary_Empty(t *testing.T) {
	s := buildSummary([]UserRecord{}, 0)
	if s.Total != 0 || s.HighRisk != 0 || s.MediumRisk != 0 || s.OK != 0 {
		t.Errorf("empty summary should be all zeros, got %+v", s)
	}
}

// ---- inGroup ----------------------------------------------------------------

func TestInGroup(t *testing.T) {
	groups := []string{"developers", "admins", "viewers"}

	if !inGroup(groups, "admins") {
		t.Error("expected to find 'admins'")
	}
	if inGroup(groups, "root") {
		t.Error("did not expect to find 'root'")
	}
	if inGroup(nil, "admins") {
		t.Error("nil group slice should return false")
	}
}
