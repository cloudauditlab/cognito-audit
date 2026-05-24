# cognito-audit

AWS Cognito User Pool のアクセス権監査 CLI ツール。

SOC2 CC6.2 / CC6.3 および ISMS A.8.2（特権アクセス管理）の定期レビューに必要な証跡を自動生成します。

**[詳細な解説記事 → Zenn](https://zenn.dev/hiro_code_lab/articles/4fb2b2656f2a00)**

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
# リージョン内の全 User Pool を表示
cognito-audit pools

# 別リージョン
cognito-audit pools --region us-east-1

# JSON 出力
cognito-audit pools --format json
```

**出力例:**

```
POOL ID                          POOL NAME        MFA CONFIG
───────────────────────────      ──────────────   ──────────
ap-northeast-1_ABC123456         myapp-prod       OPTIONAL
ap-northeast-1_XYZ789012         myapp-staging    OFF
```

---

### `scan` — User Pool を監査

```bash
# 基本スキャン（テキスト出力）
cognito-audit scan --pool-id ap-northeast-1_ABC123456

# JSON 出力（CI / jq 連携）
cognito-audit scan --pool-id ap-northeast-1_ABC123456 --format json > report.json

# CSV 出力（Excel / スプレッドシート）
cognito-audit scan --pool-id ap-northeast-1_ABC123456 --format csv > report.csv

# フラグ付きユーザーのみ表示
cognito-audit scan --pool-id ap-northeast-1_ABC123456 --flags-only

# 特定グループのみ
cognito-audit scan --pool-id ap-northeast-1_ABC123456 --group-filter admins

# 非アクティブ判定日数を変更（デフォルト 90 日）
cognito-audit scan --pool-id ap-northeast-1_ABC123456 --inactive-days 60

# 結果をファイルに保存
cognito-audit scan --pool-id ap-northeast-1_ABC123456 --output report.txt

# 別プロファイル
cognito-audit scan --pool-id ap-northeast-1_ABC123456 --profile prod-readonly
```

---

## サンプル出力

### テキスト形式

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
[MEDIUM]  dave@myapp.com           dave@myapp.com                     CONFIRMED               N   420d   -          DISABLED | STALE_420d
[OK]      eve@myapp.com            eve@myapp.com                      CONFIRMED               Y   5d     users      -
[OK]      frank@myapp.com          frank@myapp.com                    CONFIRMED               Y   60d    users      -
[OK]      grace@myapp.com          grace@myapp.com                    CONFIRMED               Y   90d    -          -
[OK]      henry@myapp.com          henry@myapp.com                    CONFIRMED               Y   15d    -          -
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

### JSON 形式（抜粋）

```json
{
  "pool": {
    "pool_id": "ap-northeast-1_ABC123456",
    "pool_name": "myapp-prod",
    "region": "ap-northeast-1",
    "mfa_config": "OPTIONAL",
    "total_users": 8
  },
  "scanned_at": "2026-05-25T10:00:00Z",
  "summary": {
    "total": 8,
    "high_risk": 2,
    "medium_risk": 2,
    "ok": 4
  },
  "users": [
    {
      "username": "alice@myapp.com",
      "email": "alice@myapp.com",
      "status": "CONFIRMED",
      "enabled": true,
      "groups": ["admins"],
      "created_at": "2025-06-14T01:23:45Z",
      "last_modified_at": "2025-06-14T01:23:45Z",
      "account_age_days": 312,
      "risk_level": "HIGH",
      "flags": ["PRIVILEGED:admins"]
    }
  ]
}
```

---

## リスク判定ロジック

| リスク | 判定条件 |
|--------|---------|
| **HIGH** | `COMPROMISED` ステータス |
| **HIGH** | `UNCONFIRMED` かつ作成から 7 日以上経過（サインアップ放置） |
| **HIGH** | `admin` / `owner` 等の特権グループに所属 |
| **MEDIUM** | `FORCE_CHANGE_PASSWORD`（招待メールを開いていない） |
| **MEDIUM** | `Enabled = false`（無効化済みがプールに残存） |
| **MEDIUM** | `CONFIRMED` かつ `UserLastModifiedDate` が N 日以上前（デフォルト 90 日） |
| **OK** | 上記以外 |

### 特権グループの判定

グループ名に `admin` `administrator` `root` `super` `owner` `operator` `ops` を含む場合に HIGH 判定します。

---

## 終了コード

| コード | 意味 |
|--------|------|
| `0` | HIGH リスクユーザーなし |
| `1` | HIGH リスクユーザーが 1 人以上存在 |

CI/CD パイプラインで定期チェックとして使えます。

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

### 最終ログイン日時は取得できない

Cognito の `ListUsers` API は **認証イベント（最終ログイン日時）を返しません**。
`STALE_Nd` フラグは `UserLastModifiedDate`（属性の最終更新日時）をプロキシとして使用します。

実際の最終ログイン日時を取得するには CloudTrail が必要です:

```bash
# CloudTrail で InitiateAuth イベントを検索
aws logs filter-log-events \
  --log-group-name /aws/cognito/userpools \
  --filter-pattern "InitiateAuth" \
  --start-time $(date -d '90 days ago' +%s000)
```

### MFA の個別ステータス

ユーザーごとの MFA 設定状態（TOTP/SMS）を取得するには `AdminGetUser` が必要です。
現バージョンはプール全体の MFA 設定（ON/OPTIONAL/OFF）のみ表示します。

---

## 対応する SOC2 / ISMS コントロール

| 標準 | コントロール | cognito-audit が証跡化する内容 |
|------|------------|-------------------------------|
| SOC2 | CC6.2 | アクセス権のある全ユーザーのリスト |
| SOC2 | CC6.3 | 不要・無効アカウントの検出 |
| ISMS | A.8.2 | 特権ユーザー（管理者グループ）の棚卸し |
| ISMS | A.8.5 | 未使用・放置アカウントの検出 |

---

## 今後の拡張案

| 優先度 | 機能 |
|--------|------|
| 高 | CloudTrail 連携による実際の最終ログイン日時取得 |
| 高 | ユーザーごとの MFA ステータス（`AdminGetUser` 対応） |
| 高 | AWS IAM ユーザー監査（アクセスキー年齢・MFA 未設定） |
| 中 | GitHub / GitLab メンバーシップ監査 |
| 中 | Slack ユーザー監査 |
| 中 | Web UI（棚卸しワークフロー・承認 PDF 生成） |
| 低 | 定期スキャン結果の差分通知（前回との比較） |

---

## ライセンス

MIT
