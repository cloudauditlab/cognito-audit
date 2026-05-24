# cognito-audit

A CLI tool to audit AWS Cognito User Pool security posture.

Automatically classifies all users as **HIGH / MEDIUM / OK** risk based on their status, group membership, and activity — no manual review needed.

**[Japanese README / 日本語はこちら](#japanese)**

**[Zenn Article (Japanese)](https://zenn.dev/hiro_code_lab/articles/4fb2b2656f2a00)**

---

## Install

```bash
go install github.com/cloudauditlab/cognito-audit@latest
```

## Quick Start

```bash
# List all User Pools in a region
cognito-audit pools --region ap-northeast-1

# Scan a User Pool
cognito-audit scan --pool-id ap-northeast-1_XXXXXXXXX --region ap-northeast-1
```

## Risk Levels

| Risk | Condition |
|------|-----------|
| **HIGH** | `COMPROMISED` status |
| **HIGH** | `UNCONFIRMED` signup older than 7 days |
| **HIGH** | Member of privileged group (admin / root / owner / operator / ops) |
| **MEDIUM** | `FORCE_CHANGE_PASSWORD` (temporary password never changed) |
| **MEDIUM** | Account disabled (`Enabled = false`) |
| **MEDIUM** | No attribute change in N days (default: 90) |
| **OK** | None of the above |

## Sample Output

```
=== Cognito User Pool Audit Report ===

  Pool ID    : ap-northeast-1_ABC123456
  Pool Name  : myapp-prod
  Region     : ap-northeast-1
  MFA Config : OPTIONAL
  Total Users: 8
  Scanned At : 2026-05-25 10:00:00 JST

Risk Summary
  [HIGH]   2
  [MEDIUM] 2
  [OK]     4

────────────────────────────────────────────────────────────────────────────────
RISK      USERNAME          EMAIL                  FLAGS
────      ────────          ─────                  ─────
[HIGH]    alice@myapp.com   alice@myapp.com         PRIVILEGED:admins
[HIGH]    bob_orphan        bob@myapp.com           UNCONFIRMED_45d
[MEDIUM]  charlie           charlie@myapp.com       FORCE_CHANGE_PASSWORD
[OK]      eve               eve@myapp.com           -
────────────────────────────────────────────────────────────────────────────────
```

## Required IAM Permissions (read-only)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cognito-idp:ListUserPools",
        "cognito-idp:DescribeUserPool",
        "cognito-idp:ListUsers",
        "cognito-idp:ListGroups",
        "cognito-idp:ListUsersInGroup"
      ],
      "Resource": "*"
    }
  ]
}
```

No write permissions required. This tool never modifies or deletes users.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No HIGH risk users found |
| `1` | One or more HIGH risk users found |

Use exit code `1` to fail CI/CD pipelines when high-risk accounts are detected.

## License

MIT

---

<a name="japanese"></a>

# cognito-audit（日本語）

AWS Cognito User Pool のアクセス権監査 CLI ツール。

SOC2 CC6.2 / CC6.3 および ISMS A.8.2（特権アクセス管理）の定期レビューに必要な証跡を自動生成します。

---

## インストール

```bash
go install github.com/cloudauditlab/cognito-audit@latest
```

または手元でビルド:

```bash
git clone https://github.com/cloudauditlab/cognito-audit
cd cognito-audit
go build -o cognito-audit .
```

---

## 必要な IAM 権限（読み取り専用）

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cognito-idp:ListUserPools",
        "cognito-idp:DescribeUserPool",
        "cognito-idp:ListUsers",
        "cognito-idp:ListGroups",
        "cognito-idp:ListUsersInGroup"
      ],
      "Resource": "*"
    }
  ]
}
```

> 書き込み権限は一切不要です。ユーザーの変更・削除は行いません。

---

## コマンド

### `pools` — User Pool 一覧

```bash
cognito-audit pools
cognito-audit pools --region us-east-1
cognito-audit pools --format json
```

### `scan` — User Pool を監査

```bash
cognito-audit scan --pool-id ap-northeast-1_ABC123456
cognito-audit scan --pool-id ap-northeast-1_ABC123456 --format json > report.json
cognito-audit scan --pool-id ap-northeast-1_ABC123456 --format csv > report.csv
cognito-audit scan --pool-id ap-northeast-1_ABC123456 --flags-only
cognito-audit scan --pool-id ap-northeast-1_ABC123456 --inactive-days 60
cognito-audit scan --pool-id ap-northeast-1_ABC123456 --group-filter admins
cognito-audit scan --pool-id ap-northeast-1_ABC123456 --profile prod-readonly
```

---

## サンプル出力

```
=== Cognito User Pool Audit Report ===

  Pool ID    : ap-northeast-1_ABC123456
  Pool Name  : myapp-prod
  Region     : ap-northeast-1
  MFA Config : OPTIONAL  (users may not have MFA)
  Total Users: 8
  Scanned At : 2026-05-25 10:00:00 JST

Risk Summary
  [HIGH]   2
  [MEDIUM] 2
  [OK]     4

────────────────────────────────────────────────────────────────────────────────────────────────────────
RISK      USERNAME                 EMAIL                              STATUS                  ON  AGE    GROUPS     FLAGS
────────  ────────                 ─────                              ──────                  ──  ───    ──────     ─────
[HIGH]    alice@myapp.com          alice@myapp.com                    CONFIRMED               Y   312d   admins     PRIVILEGED:admins
[HIGH]    bob_orphan               bob@myapp.com                      UNCONFIRMED             Y   45d    -          UNCONFIRMED_45d
[MEDIUM]  charlie@myapp.com        charlie@myapp.com                  FORCE_CHANGE_PASSWORD   Y   30d    -          FORCE_CHANGE_PASSWORD
[MEDIUM]  dave@myapp.com           dave@myapp.com                     CONFIRMED               N   420d   -          DISABLED
[OK]      eve@myapp.com            eve@myapp.com                      CONFIRMED               Y   5d     users      -
────────────────────────────────────────────────────────────────────────────────────────────────────────

Flag Legend:
  COMPROMISED           - Account marked compromised by Cognito
  UNCONFIRMED_Nd        - Signup never completed, N days old
  FORCE_CHANGE_PASSWORD - Temporary password never changed
  DISABLED              - Account disabled but still in pool
  STALE_Nd              - No attribute change in N days (*not* last-login)
  PRIVILEGED:<group>    - Member of a privileged group

NOTE: STALE uses UserLastModifiedDate as a staleness proxy.
      For actual last-login, enable CloudTrail and query InitiateAuth events.
```

---

## リスク判定ロジック

| リスク | 判定条件 |
|--------|---------|
| **HIGH** | `COMPROMISED` ステータス |
| **HIGH** | `UNCONFIRMED` かつ作成から 7 日以上経過 |
| **HIGH** | `admin` / `owner` 等の特権グループに所属 |
| **MEDIUM** | `FORCE_CHANGE_PASSWORD` |
| **MEDIUM** | `Enabled = false` |
| **MEDIUM** | `UserLastModifiedDate` が N 日以上前（デフォルト 90 日） |
| **OK** | 上記以外 |

---

## 終了コード

| コード | 意味 |
|--------|------|
| `0` | HIGH リスクユーザーなし |
| `1` | HIGH リスクユーザーが 1 人以上存在 |

```yaml
# GitLab CI 例
cognito-access-review:
  stage: security
  script:
    - cognito-audit scan --pool-id $COGNITO_POOL_ID --flags-only
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
```

---

## 既知の制限

**最終ログイン日時は取得できません。** Cognito の `ListUsers` API は認証イベントを返しません。`STALE_Nd` は `UserLastModifiedDate` をプロキシとして使用します。実際の最終ログイン日時には CloudTrail が必要です。

---

## 対応する SOC2 / ISMS コントロール

| 標準 | コントロール | 内容 |
|------|------------|------|
| SOC2 | CC6.2 | アクセス権のある全ユーザーのリスト |
| SOC2 | CC6.3 | 不要・無効アカウントの検出 |
| ISMS | A.8.2 | 特権ユーザーの棚卸し |
| ISMS | A.8.5 | 未使用・放置アカウントの検出 |

---

## ライセンス

MIT
