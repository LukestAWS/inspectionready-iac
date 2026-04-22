terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# IAM Account Password Policy
# CQC Reg 17 | DSPT Assertion 7 (cyber security — access control)
#
# Enforces strong password requirements across all IAM users in the account.
# AWS does not enforce password policies by default — this is a frequent
# Prowler finding in unaudited care provider environments.
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_iam_account_password_policy" "this" {
  minimum_password_length        = 14
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  hard_expiry                    = false
}

# ─────────────────────────────────────────────────────────────────────────────
# IAM Access Analyzer
# CQC Reg 17 | DSPT Assertion 6 (cyber security — network and cloud security)
#
# Continuously monitors resource-based policies and flags any resource that
# is unintentionally shared outside the account boundary. Catches S3 buckets,
# IAM roles, KMS keys, and Lambda functions with overly permissive policies.
#
# Zone of trust: ACCOUNT — findings raised for any external principal access.
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_accessanalyzer_analyzer" "this" {
  analyzer_name = "${var.client_name}-access-analyzer"
  type          = "ACCOUNT"

  tags = merge(var.tags, {
    Name      = "${var.client_name}-access-analyzer"
    Module    = "identity"
    ManagedBy = "InspectionReady"
  })
}

# ─────────────────────────────────────────────────────────────────────────────
# Cross-Account Audit Role
# CQC Reg 17 | DSPT Assertion 6 + 7
#
# Grants InspectionReady Systems secure, time-limited access to the client
# environment for audit and remediation. No credentials are stored.
# Every action taken via this role is logged in the client's CloudTrail.
#
# Security controls:
#   - ExternalId condition prevents confused deputy attacks
#   - 1-hour max session duration limits blast radius
#   - SecurityAudit + ReadOnlyAccess managed policies — no write permissions
#     beyond what remediation tasks require (inline policies added per-task)
#
# Client action required: provide the output cross_account_role_arn to
# InspectionReady Systems to complete onboarding.
# ─────────────────────────────────────────────────────────────────────────────
data "aws_iam_policy_document" "cross_account_assume" {
  statement {
    sid    = "AllowInspectionReadyAssumeRole"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.inspectionready_account_id}:root"]
    }

    actions = ["sts:AssumeRole"]

    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.external_id]
    }
  }
}

resource "aws_iam_role" "cross_account_audit" {
  name                 = "InspectionReady-AuditRole"
  description          = "Cross-account role for InspectionReady Systems. Audit and remediation access. All actions logged in CloudTrail."
  assume_role_policy   = data.aws_iam_policy_document.cross_account_assume.json
  max_session_duration = 3600

  tags = merge(var.tags, {
    Name      = "InspectionReady-AuditRole"
    Module    = "identity"
    ManagedBy = "InspectionReady"
    Purpose   = "Audit and remediation — InspectionReady Systems engagement"
  })
}

resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.cross_account_audit.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "read_only" {
  role       = aws_iam_role.cross_account_audit.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}
