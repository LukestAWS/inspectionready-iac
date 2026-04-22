# initial-state

**InspectionReady Systems — Pre-Engagement Baseline Capture Module**

---

## What this module does

`initial-state` reads the complete security, cost, and compliance posture of a client AWS account and writes every finding into Terraform output values and state.  It covers eight categories:

| Category | What is captured |
|---|---|
| **Identity** | IAM password policy · all users with access-key metadata · virtual MFA device assignments · count of users without MFA · all roles with admin-name heuristic flag |
| **Data** | All S3 buckets (all regions) with public-access block, versioning, server-access logging, and object-lock status · RDS instances (encryption + public accessibility) · EBS volumes (encryption status) |
| **Network** | All VPCs with default-VPC detection · security groups with unrestricted IPv4/IPv6 ingress · VPC IDs flagged for manual flow-log verification |
| **Monitoring & Logging** | CloudTrail service account · GuardDuty detector · CloudWatch Log Groups with retention periods · AWS Config recorder · SNS topics |
| **Billing & Cost** | CloudWatch billing alarms · 90-day Cost Explorer spend by service · 90-day Cost Explorer spend by region |
| **Compliance** | Security Hub hub status · customer-managed KMS keys with rotation flag · Secrets Manager secret inventory |
| **Organisation** | Organisation membership · management vs. member account determination · member account count |
| **Care Sector Integrations** | All Lambda functions with environment-variable key audit · EventBridge rules on the default event bus |

---

## Safety guarantee — ZERO resource blocks

This module contains **only `data` blocks and `locals`**.  It will never create, modify, or destroy any resource in the target account.  You can verify this at any time:

```bash
grep -c "^resource" main.tf   # must print 0
```

Running `terraform apply` against this module is safe — it is functionally equivalent to `terraform plan` or `terraform apply -refresh-only` because there are no resources to apply.

---

## When to run this module

> **Run `initial-state` first — before every other module, and before any manual remediation work begins.**

The Terraform state snapshot produced by this module is the authoritative **before** record for the engagement.  Any remediation applied before running `initial-state` will not appear in the baseline, invalidating the 70 % cost-reduction guarantee comparison.

Correct order of execution:

```
1.  initial-state          ← this module  (run once at engagement start)
2.  identity               ← IAM hardening
3.  monitoring             ← GuardDuty / CloudTrail / Config
4.  security-hub           ← Security Hub standards
5.  data-protection        ← S3 / KMS / Secrets Manager
6.  guardduty              ← detector tuning
7.  ... (other remediation modules)
8.  initial-state          ← run again at engagement close to capture after-state
```

---

## Prerequisites

### 1 — Cost Explorer must be enabled

The `billing_ce_by_service_90d` and `billing_ce_by_region_90d` outputs use the `aws_ce_cost_and_usage` Terraform data source, which calls the AWS Cost Explorer API.  Cost Explorer must be **activated** in the account before this module is run, or the plan will fail with a permissions error.

To activate Cost Explorer:

1. Sign in to the AWS Console as the management account root or a billing-access IAM user.
2. Navigate to **Billing and Cost Management → Cost Explorer**.
3. Click **Enable Cost Explorer** and wait approximately 24 hours for historical data to populate.

Cost Explorer activation is free; query charges apply at AWS list rates (typically $0.01 per API request).

### 2 — Caller permissions

The IAM principal running this module needs read-only access across all services.  The AWS-managed policy `ReadOnlyAccess` (arn:aws:iam::aws:policy/ReadOnlyAccess) is sufficient for most data sources.  Additional permissions may be required for:

- `ce:GetCostAndUsage` (Cost Explorer)
- `organizations:Describe*` (AWS Organizations — only if the account is an org member)
- `securityhub:DescribeHub` (Security Hub)
- `guardduty:GetDetector` (GuardDuty)

### 3 — Terraform and provider versions

| Requirement | Minimum version |
|---|---|
| Terraform | 1.5.0 |
| hashicorp/aws provider | 5.31.0 |
| aws_lambda_functions data source | 5.34.0 |

---

## Usage

```hcl
module "initial_state" {
  source = "./modules/initial-state"

  aws_account_id       = "123456789012"
  aws_region           = "eu-west-2"          # default; override if needed
  client_name          = "Acme NHS Trust"
  engagement_reference = "IR-2026-001"
}
```

Configure the AWS provider in the calling root module:

```hcl
provider "aws" {
  region = "eu-west-2"
  # Assume the client's read-only cross-account role if running from
  # InspectionReady's management account:
  assume_role {
    role_arn = "arn:aws:iam::123456789012:role/InspectionReadyReadOnly"
  }
}
```

Run the capture:

```bash
terraform init
terraform apply -refresh-only   # safest invocation — reads state only
# or
terraform plan                  # equivalent for a data-source-only module
```

Save the output to a file for the engagement record:

```bash
terraform output -json > engagement-IR-2026-001-before-state.json
```

---

## Outputs and the 70 % cost-reduction guarantee

The outputs of this module form the **before-state** of the InspectionReady engagement.  Specifically:

- `billing_ce_by_service_90d` — 90-day spend by service immediately before remediation.
- `billing_ce_by_region_90d` — 90-day spend by region to surface shadow IT and misrouted traffic.
- `data_s3_summary`, `data_ebs_unencrypted_volumes`, `data_rds_instance_detail` — storage exposure surface before data-protection remediation.

At engagement close, the `initial-state` module is run a second time to produce the **after-state**.  The delta between before and after is the evidence base for the 70 % cloud-cost-reduction guarantee.

**Do not remediate anything before running this module.**

---

## Audit trail output

The `audit_trail` output records:

| Field | Content |
|---|---|
| `captured_at` | ISO 8601 timestamp when Terraform evaluated the data sources |
| `caller_arn` | ARN of the IAM principal that executed the module |
| `caller_user_id` | IAM user or assumed-role session ID |
| `account_id` | AWS account ID confirmed at runtime (cross-checks `var.aws_account_id`) |
| `region` | AWS region of execution |
| `client_name` | Value of `var.client_name` |
| `engagement_ref` | Value of `var.engagement_reference` |

The `captured_at` timestamp is the **official engagement-start time** used in all InspectionReady reports and service agreements.  It is stored in Terraform state and is immutable once written.

---

## Manual steps required

Several AWS services cannot be enumerated via Terraform data sources.  The following CLI commands must be run separately and their output appended to the engagement record:

```bash
# CloudTrail — all trails including multi-region
aws cloudtrail describe-trails --include-shadow-trails \
  --query 'trailList[*].{Name:Name,HomeRegion:HomeRegion,MultiRegion:IsMultiRegionTrail,S3Bucket:S3BucketName,LogValidation:LogFileValidationEnabled}'

# IAM Access Analyzer
aws accessanalyzer list-analyzers \
  --query 'analyzers[*].{Name:name,Type:type,Status:status}'

# AWS Budgets
aws budgets describe-budgets --account-id <ACCOUNT_ID> \
  --query 'Budgets[*].{Name:BudgetName,Type:BudgetType,Limit:BudgetLimit,ActualSpend:CalculatedSpend.ActualSpend}'

# VPC Flow Logs (per VPC — repeat for each VPC ID in network_vpc_ids output)
aws ec2 describe-flow-logs \
  --filter Name=resource-id,Values=<VPC_ID> \
  --query 'FlowLogs[*].{Status:FlowLogStatus,Dest:LogDestinationType,DestARN:LogDestination}'

# Hardware MFA devices (per user — repeat for each user in identity_all_user_names)
aws iam list-mfa-devices --user-name <USERNAME> \
  --query 'MFADevices[*].{Serial:SerialNumber,Type:SerialNumber}'

# Console access per user (login profile = console enabled)
aws iam get-login-profile --user-name <USERNAME> 2>&1

# AdministratorAccess attached policies (per role — check all roles in identity_roles_heuristic_admin)
aws iam list-attached-role-policies --role-name <ROLE> \
  --query 'AttachedPolicies[?PolicyName==`AdministratorAccess`]'
```

---

## Known limitations

| Limitation | Workaround |
|---|---|
| CloudTrail trail listing not available via data source | CLI: `aws cloudtrail describe-trails` |
| IAM Access Analyzer listing not available | CLI: `aws accessanalyzer list-analyzers` |
| AWS Budgets listing not available | CLI: `aws budgets describe-budgets` |
| VPC Flow Log status not available | CLI: `aws ec2 describe-flow-logs` per VPC |
| Hardware MFA device detection not available | CLI: `aws iam list-mfa-devices` per user |
| Managed policy attachments per role not available | CLI: `aws iam list-attached-role-policies` per role |
| GuardDuty / Security Hub / Config errors on disabled services | Plan failure = finding; record service as disabled |
| Lambda env-var VALUES excluded from state | By design — prevents secret capture in state file |
| Billing CloudWatch alarms are in us-east-1 only | Re-run with `aws_region = "us-east-1"` for billing alarm coverage |

---

## Deployment Notes — First Run on a Client Account

### 1. Use a Local Backend
During the initial-state capture phase, keep the Terraform state file on your encrypted consultancy machine. Do not configure a remote backend (S3, Terraform Cloud) until after the engagement scope is agreed and the client environment is secured. The state file contains a snapshot of their entire security posture — treat it as regulated data.

### 2. Redirect Output to a File
The outputs.tf file is extensive. Console output will be unreadable. Always run:
`terraform output -json > [client_name]_[engagement_ref]_initial_state.json`
This produces a machine-readable audit trail you can reference throughout the engagement and include as evidence in the final report.

### 3. Store the Output File Securely
The JSON output contains account IDs, resource ARNs, IAM user lists, and cost data. File it immediately to the per-client engagement folder. Do not leave it in the IaC directory. Delete it from the local IaC folder after filing.
