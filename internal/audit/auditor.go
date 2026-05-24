package audit

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	ciptypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

// Options controls the behaviour of a scan.
type Options struct {
	PoolID       string
	Region       string
	Profile      string
	InactiveDays int
	GroupFilter  string
	FlagsOnly    bool
}

// Run executes a full audit of a Cognito User Pool.
func Run(ctx context.Context, opts Options) (*Report, error) {
	client, err := newClient(ctx, opts.Region, opts.Profile)
	if err != nil {
		return nil, err
	}

	pool, err := describePool(ctx, client, opts.PoolID, opts.Region)
	if err != nil {
		return nil, fmt.Errorf("describe pool: %w", err)
	}

	groupMembership, err := buildGroupMembership(ctx, client, opts.PoolID)
	if err != nil {
		return nil, fmt.Errorf("build group membership: %w", err)
	}

	rawUsers, err := listAllUsers(ctx, client, opts.PoolID)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}

	pool.TotalUsers = len(rawUsers)
	now := time.Now()

	var records []UserRecord
	for _, u := range rawUsers {
		rec := convertUser(u, groupMembership, now, opts.InactiveDays)

		if opts.GroupFilter != "" && !inGroup(rec.Groups, opts.GroupFilter) {
			continue
		}
		if opts.FlagsOnly && len(rec.Flags) == 0 {
			continue
		}
		records = append(records, rec)
	}

	sort.Slice(records, func(i, j int) bool {
		si, sj := riskScore(records[i].RiskLevel), riskScore(records[j].RiskLevel)
		if si != sj {
			return si > sj
		}
		return records[i].Username < records[j].Username
	})

	return &Report{
		Pool:      *pool,
		ScannedAt: now,
		Users:     records,
		Summary:   buildSummary(records, len(rawUsers)),
	}, nil
}

// ListPools returns all User Pools in the region.
func ListPools(ctx context.Context, region, profile string) ([]PoolSummaryItem, error) {
	client, err := newClient(ctx, region, profile)
	if err != nil {
		return nil, err
	}

	var pools []PoolSummaryItem
	var nextToken *string

	for {
		resp, err := client.ListUserPools(ctx, &cognitoidentityprovider.ListUserPoolsInput{
			MaxResults: aws.Int32(60),
			NextToken:  nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("list user pools: %w", err)
		}
		for _, p := range resp.UserPools {
			detail, err := client.DescribeUserPool(ctx, &cognitoidentityprovider.DescribeUserPoolInput{
				UserPoolId: p.Id,
			})
			mfa := "UNKNOWN"
			if err == nil {
				mfa = string(detail.UserPool.MfaConfiguration)
			}
			pools = append(pools, PoolSummaryItem{
				PoolID:    aws.ToString(p.Id),
				PoolName:  aws.ToString(p.Name),
				MFAConfig: mfa,
			})
		}
		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}
	return pools, nil
}

// ---- private ----------------------------------------------------------------

func newClient(ctx context.Context, region, profile string) (*cognitoidentityprovider.Client, error) {
	opts := []func(*config.LoadOptions) error{
		config.WithRegion(region),
	}
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return cognitoidentityprovider.NewFromConfig(cfg), nil
}

func describePool(ctx context.Context, client *cognitoidentityprovider.Client, poolID, region string) (*PoolInfo, error) {
	resp, err := client.DescribeUserPool(ctx, &cognitoidentityprovider.DescribeUserPoolInput{
		UserPoolId: aws.String(poolID),
	})
	if err != nil {
		return nil, err
	}
	return &PoolInfo{
		PoolID:    poolID,
		PoolName:  aws.ToString(resp.UserPool.Name),
		Region:    region,
		MFAConfig: string(resp.UserPool.MfaConfiguration),
	}, nil
}

// buildGroupMembership returns username → []groupName for all groups in the pool.
func buildGroupMembership(ctx context.Context, client *cognitoidentityprovider.Client, poolID string) (map[string][]string, error) {
	// 1. list all groups
	var groups []ciptypes.GroupType
	var nextToken *string
	for {
		resp, err := client.ListGroups(ctx, &cognitoidentityprovider.ListGroupsInput{
			UserPoolId: aws.String(poolID),
			NextToken:  nextToken,
		})
		if err != nil {
			return nil, err
		}
		groups = append(groups, resp.Groups...)
		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}

	// 2. for each group, collect members
	membership := make(map[string][]string)
	for _, g := range groups {
		groupName := aws.ToString(g.GroupName)
		var pageToken *string
		for {
			resp, err := client.ListUsersInGroup(ctx, &cognitoidentityprovider.ListUsersInGroupInput{
				UserPoolId: aws.String(poolID),
				GroupName:  aws.String(groupName),
				NextToken:  pageToken,
			})
			if err != nil {
				return nil, fmt.Errorf("list users in group %s: %w", groupName, err)
			}
			for _, u := range resp.Users {
				un := aws.ToString(u.Username)
				membership[un] = append(membership[un], groupName)
			}
			if resp.NextToken == nil {
				break
			}
			pageToken = resp.NextToken
		}
	}
	return membership, nil
}

func listAllUsers(ctx context.Context, client *cognitoidentityprovider.Client, poolID string) ([]ciptypes.UserType, error) {
	var users []ciptypes.UserType
	var pageToken *string
	for {
		resp, err := client.ListUsers(ctx, &cognitoidentityprovider.ListUsersInput{
			UserPoolId:      aws.String(poolID),
			Limit:           aws.Int32(60),
			PaginationToken: pageToken,
		})
		if err != nil {
			return nil, err
		}
		users = append(users, resp.Users...)
		if resp.PaginationToken == nil {
			break
		}
		pageToken = resp.PaginationToken
	}
	return users, nil
}

func convertUser(u ciptypes.UserType, membership map[string][]string, now time.Time, inactiveDays int) UserRecord {
	username := aws.ToString(u.Username)

	attrs := make(map[string]string, len(u.Attributes))
	for _, a := range u.Attributes {
		attrs[aws.ToString(a.Name)] = aws.ToString(a.Value)
	}

	createdAt := aws.ToTime(u.UserCreateDate)
	lastModAt := aws.ToTime(u.UserLastModifiedDate)
	ageDays := int(now.Sub(createdAt).Hours() / 24)

	groups := membership[username]
	if groups == nil {
		groups = []string{}
	}

	rec := UserRecord{
		Username:       username,
		Email:          attrs["email"],
		Name:           attrs["name"],
		Status:         string(u.UserStatus),
		Enabled:        u.Enabled,
		Groups:         groups,
		CreatedAt:      createdAt,
		LastModifiedAt: lastModAt,
		AccountAgeDays: ageDays,
	}
	evaluateRisk(&rec, inactiveDays, now)
	return rec
}

func evaluateRisk(r *UserRecord, inactiveDays int, now time.Time) {
	level := RiskOK

	// HIGH: account compromised
	if r.Status == "COMPROMISED" {
		r.Flags = append(r.Flags, "COMPROMISED")
		level = maxRisk(level, RiskHigh)
	}

	// HIGH: unconfirmed and old (orphaned signup)
	if r.Status == "UNCONFIRMED" && r.AccountAgeDays > 7 {
		r.Flags = append(r.Flags, fmt.Sprintf("UNCONFIRMED_%dd", r.AccountAgeDays))
		level = maxRisk(level, RiskHigh)
	}

	// HIGH: member of a privileged group
	for _, g := range r.Groups {
		if isPrivilegedGroup(g) {
			r.Flags = append(r.Flags, "PRIVILEGED:"+g)
			level = maxRisk(level, RiskHigh)
		}
	}

	// MEDIUM: password reset required (created but never activated)
	if r.Status == "FORCE_CHANGE_PASSWORD" {
		r.Flags = append(r.Flags, "FORCE_CHANGE_PASSWORD")
		level = maxRisk(level, RiskMedium)
	}

	// MEDIUM: account disabled but still present in pool
	if !r.Enabled {
		r.Flags = append(r.Flags, "DISABLED")
		level = maxRisk(level, RiskMedium)
	}

	// MEDIUM: no attribute change for N days (staleness proxy — not actual last-login)
	threshold := now.AddDate(0, 0, -inactiveDays)
	if r.LastModifiedAt.Before(threshold) && r.Status == "CONFIRMED" && r.Enabled {
		days := int(now.Sub(r.LastModifiedAt).Hours() / 24)
		r.Flags = append(r.Flags, fmt.Sprintf("STALE_%dd", days))
		level = maxRisk(level, RiskMedium)
	}

	r.RiskLevel = level
}

// isPrivilegedGroup returns true for groups whose names suggest elevated access.
func isPrivilegedGroup(name string) bool {
	lower := strings.ToLower(name)
	privileged := []string{"admin", "administrator", "root", "super", "owner", "operator", "ops"}
	for _, kw := range privileged {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func inGroup(groups []string, target string) bool {
	for _, g := range groups {
		if g == target {
			return true
		}
	}
	return false
}

func buildSummary(records []UserRecord, total int) Summary {
	s := Summary{Total: total}
	for _, r := range records {
		switch r.RiskLevel {
		case RiskHigh:
			s.HighRisk++
		case RiskMedium:
			s.MediumRisk++
		default:
			s.OK++
		}
	}
	return s
}
