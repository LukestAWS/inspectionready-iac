###############################################################################
# InspectionReady Systems — Initial State Capture Module
# main.tf
#
# PURPOSE  : Read the complete security, cost, and compliance posture of a
#            client AWS account before any remediation work begins.
# SAFETY   : ZERO resource blocks.  This module only reads; it never writes,
#            modifies, or destroys anything in the target account.
# USAGE    : terraform init && terraform apply -refresh-only
#            (or terraform plan; the plan phase reads all data sources)
# ORDER    : Run BEFORE every other module and BEFORE any manual remediation.
###############################################################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.31.0"
    }
  }
}

###############################################################################
# AUDIT TRAIL
# Captures who ran this module, when, and for which engagement.
# The timestamp is the authoritative start-of-engagement marker used to
# anchor the 70 % cost-reduction guarantee baseline period.
###############################################################################

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

locals {
  # timestamp() is evaluated at plan/apply time and recorded in state.
  execution_timestamp = timestamp()

  audit_trail = {
    captured_at      = local.execution_timestamp
    caller_arn       = data.aws_caller_identity.current.arn
    caller_user_id   = data.aws_caller_identity.current.user_id
    account_id       = data.aws_caller_identity.current.account_id
    region           = data.aws_region.current.name
    client_name      = var.client_name
    engagement_ref   = var.engagement_reference
  }
}

###############################################################################
# IDENTITY
###############################################################################

# ── Password policy ──────────────────────────────────────────────────────────

data "aws_iam_account_password_policy" "current" {}

# ── IAM users ────────────────────────────────────────────────────────────────

data "aws_iam_users" "all" {}

# Per-user detail — used for group memberships, path, create date, tags.
data "aws_iam_user" "all" {
  for_each  = toset(data.aws_iam_users.all.names)
  user_name = each.value
}

# Access keys per user (status: Active / Inactive, create date).
data "aws_iam_access_keys" "all" {
  for_each = toset(data.aws_iam_users.all.names)
  user     = each.value
}

# Virtual MFA devices assigned in this account.
# NOTE: Hardware MFA devices (physical tokens, U2F/WebAuthn keys) are NOT
# enumerable via Terraform data sources.  Supplement with:
#   aws iam list-mfa-devices --user-name <USERNAME>
# NOTE: Console-access detection (login profile) also requires the CLI:
#   aws iam get-login-profile --user-name <USERNAME>
data "aws_iam_virtual_mfa_devices" "all" {}

# ── IAM roles ────────────────────────────────────────────────────────────────

data "aws_iam_roles" "all" {}

data "aws_iam_role" "all" {
  for_each = toset(data.aws_iam_roles.all.names)
  name     = each.value
}

# NOTE: The AWS Terraform provider has no data source for listing managed
# policies attached to a given role (no aws_iam_role_policy_attachments data
# source exists).  Detecting AdministratorAccess attachment programmatically
# requires the CLI:
#   aws iam list-attached-role-policies --role-name <ROLE>
# or AWS Config rule iam-policy-in-use / SecurityHub finding.
# The heuristic local below flags roles by name pattern only and must be
# confirmed manually for every flagged role in the engagement report.

locals {
  # ── MFA analysis ────────────────────────────────────────────────────────
  # Virtual MFA serial format: arn:aws:iam::ACCOUNT:mfa/SERIAL_NAME
  # For user-assigned virtual MFA the SERIAL_NAME is typically the IAM
  # username (set by the console default).  Custom serial names will break
  # this mapping — cross-check with aws iam list-virtual-mfa-devices.
  users_with_virtual_mfa = toset([
    for device in data.aws_iam_virtual_mfa_devices.all.virtual_mfa_devices :
    element(split("/", device.serial_number), length(split("/", device.serial_number)) - 1)
    if device.serial_number != null
  ])

  # Approximate set of users without ANY virtual MFA device.
  # Does not account for hardware MFA — treat as a floor, not a ceiling.
  users_without_virtual_mfa       = setsubtract(toset(data.aws_iam_users.all.names), local.users_with_virtual_mfa)
  count_users_without_virtual_mfa = length(local.users_without_virtual_mfa)

  # ── Access key summary ───────────────────────────────────────────────────
  users_access_key_summary = {
    for user, keys in data.aws_iam_access_keys.all :
    user => {
      active_key_count   = length([for k in keys.access_keys : k if k.status == "Active"])
      inactive_key_count = length([for k in keys.access_keys : k if k.status == "Inactive"])
      keys               = keys.access_keys
    }
  }

  users_with_multiple_active_keys = {
    for user, summary in local.users_access_key_summary :
    user => summary
    if summary.active_key_count > 1
  }

  # ── Role AdministratorAccess heuristic ──────────────────────────────────
  # Flags roles whose NAME matches common administrator naming conventions.
  # MUST be confirmed via CLI before inclusion in the engagement report.
  roles_heuristic_admin = {
    for name, role in data.aws_iam_role.all :
    name => role.arn
    if can(regex("(?i)(admin|break.?glass|superuser|full.?access|poweruser|root)", name))
  }
}

###############################################################################
# DATA
###############################################################################

# ── S3 ───────────────────────────────────────────────────────────────────────
# S3 is a global service; this lists buckets regardless of region.

data "aws_s3_buckets" "all" {}

data "aws_s3_bucket" "all" {
  for_each = toset(data.aws_s3_buckets.all.buckets)
  bucket   = each.value
}

data "aws_s3_bucket_public_access_block" "all" {
  for_each = toset(data.aws_s3_buckets.all.buckets)
  bucket   = each.value
}

data "aws_s3_bucket_versioning" "all" {
  for_each = toset(data.aws_s3_buckets.all.buckets)
  bucket   = each.value
}

data "aws_s3_bucket_logging" "all" {
  for_each = toset(data.aws_s3_buckets.all.buckets)
  bucket   = each.value
}

data "aws_s3_bucket_object_lock_configuration" "all" {
  for_each = toset(data.aws_s3_buckets.all.buckets)
  bucket   = each.value
}

locals {
  # Buckets hosted outside the primary engagement region.
  buckets_outside_primary_region = {
    for name, bucket in data.aws_s3_bucket.all :
    name => bucket.region
    if bucket.region != var.aws_region
  }

  # Buckets where all four public-access block settings are NOT fully enabled.
  buckets_with_public_access_risk = {
    for name, pab in data.aws_s3_bucket_public_access_block.all :
    name => {
      block_public_acls       = try(pab.block_public_acls, false)
      block_public_policy     = try(pab.block_public_policy, false)
      ignore_public_acls      = try(pab.ignore_public_acls, false)
      restrict_public_buckets = try(pab.restrict_public_buckets, false)
    }
    if !(
      try(pab.block_public_acls, false) &&
      try(pab.block_public_policy, false) &&
      try(pab.ignore_public_acls, false) &&
      try(pab.restrict_public_buckets, false)
    )
  }

  # Buckets without versioning enabled.
  buckets_without_versioning = {
    for name, ver in data.aws_s3_bucket_versioning.all :
    name => try(ver.versioning_configuration[0].status, "Disabled")
    if try(ver.versioning_configuration[0].status, "Disabled") != "Enabled"
  }

  # Buckets with no server access logging target configured.
  buckets_without_logging = {
    for name, log in data.aws_s3_bucket_logging.all :
    name => name
    if try(log.target_bucket, "") == ""
  }

  # Buckets with object lock disabled.
  buckets_without_object_lock = {
    for name, ol in data.aws_s3_bucket_object_lock_configuration.all :
    name => name
    if try(ol.object_lock_enabled, "Disabled") != "Enabled"
  }

  s3_summary = {
    total_bucket_count             = length(data.aws_s3_buckets.all.buckets)
    outside_primary_region_count   = length(local.buckets_outside_primary_region)
    without_versioning_count       = length(local.buckets_without_versioning)
    without_logging_count          = length(local.buckets_without_logging)
    without_object_lock_count      = length(local.buckets_without_object_lock)
    with_public_access_risk_count  = length(local.buckets_with_public_access_risk)
  }
}

# ── RDS ──────────────────────────────────────────────────────────────────────

data "aws_db_instances" "all" {}

data "aws_db_instance" "all" {
  for_each               = toset(data.aws_db_instances.all.instance_identifiers)
  db_instance_identifier = each.value
}

locals {
  rds_unencrypted = {
    for id, db in data.aws_db_instance.all :
    id => db.db_instance_arn
    if !db.storage_encrypted
  }

  rds_publicly_accessible = {
    for id, db in data.aws_db_instance.all :
    id => db.db_instance_arn
    if db.publicly_accessible
  }
}

# ── EBS volumes ──────────────────────────────────────────────────────────────

data "aws_ebs_volumes" "all" {}

data "aws_ebs_volume" "all" {
  for_each    = toset(data.aws_ebs_volumes.all.ids)
  most_recent = true

  filter {
    name   = "volume-id"
    values = [each.value]
  }
}

locals {
  ebs_unencrypted_volumes = {
    for id, vol in data.aws_ebs_volume.all :
    id => {
      availability_zone = vol.availability_zone
      size              = vol.size
      volume_type       = vol.volume_type
      state             = vol.state
    }
    if !vol.encrypted
  }
}

###############################################################################
# NETWORK
###############################################################################

data "aws_vpcs" "all" {}

data "aws_vpc" "all" {
  for_each = toset(data.aws_vpcs.all.ids)
  id       = each.value
}

# Security groups allowing unrestricted IPv4 ingress from the internet.
data "aws_security_groups" "open_ingress_ipv4" {
  filter {
    name   = "ip-permission.cidr"
    values = ["0.0.0.0/0"]
  }
}

# Security groups allowing unrestricted IPv6 ingress from the internet.
data "aws_security_groups" "open_ingress_ipv6" {
  filter {
    name   = "ip-permission.ipv6-cidr"
    values = ["::/0"]
  }
}

# NOTE: The AWS Terraform provider does NOT include a data source for VPC Flow
# Logs (there is no aws_flow_log / aws_flow_logs data source).
# Determine flow-log status per VPC with the CLI:
#   aws ec2 describe-flow-logs \
#     --filter Name=resource-id,Values=<VPC_ID> \
#     --query 'FlowLogs[*].{LogStatus:LogStatus,Dest:LogDestinationType}'
# The vpc_ids_requiring_flow_log_verification local below surfaces all VPC IDs
# so the analyst can iterate with the command above during the walkthrough.

locals {
  default_vpc_exists = anytrue([
    for id, vpc in data.aws_vpc.all : vpc.default
  ])

  default_vpc_ids = [
    for id, vpc in data.aws_vpc.all : id
    if vpc.default == true
  ]

  vpc_summary = {
    for id, vpc in data.aws_vpc.all :
    id => {
      cidr_block      = vpc.cidr_block
      is_default      = vpc.default
      state           = vpc.state
      dhcp_options_id = vpc.dhcp_options_id
      tags            = vpc.tags
    }
  }

  # All VPC IDs — the analyst must verify flow-log coverage for each.
  vpc_ids_requiring_flow_log_verification = toset(data.aws_vpcs.all.ids)

  # Combined set of open security group IDs (IPv4 + IPv6).
  open_ingress_sg_ids = toset(concat(
    data.aws_security_groups.open_ingress_ipv4.ids,
    data.aws_security_groups.open_ingress_ipv6.ids
  ))
}

###############################################################################
# MONITORING AND LOGGING
###############################################################################

# NOTE: The AWS Terraform provider has no data source for listing all CloudTrail
# trails (aws_cloudtrail_trails does not exist as of provider 5.x).
# Enumerate all trails — including shadow trails in other regions — with:
#   aws cloudtrail describe-trails --include-shadow-trails \
#     --query 'trailList[*].{Name:Name,HomeRegion:HomeRegion,MultiRegion:IsMultiRegionTrail,LoggingEnabled:HasCustomEventSelectors}'
# Once trail ARNs are known, individual trails can be read with
# data "aws_cloudtrail" { trail_arn = "..." }.
# The cloudtrail_service_account data source below captures the regional AWS
# service-account ID used in S3 bucket policies for log delivery.
data "aws_cloudtrail_service_account" "current" {}

# GuardDuty detector in the current region.
# NOTE: Returns an error if GuardDuty is not enabled in this region.
# A plan error here IS a finding — record GuardDuty as disabled.
data "aws_guardduty_detector" "current" {}

# NOTE: The AWS Terraform provider requires the analyzer NAME for
# aws_accessanalyzer_analyzer (no plural listing data source exists).
# List analyzers in this region with:
#   aws accessanalyzer list-analyzers \
#     --query 'analyzers[*].{Name:name,Type:type,Status:status}'
# To read a specific analyzer once its name is known, add:
#   data "aws_accessanalyzer_analyzer" "current" { analyzer_name = "<NAME>" }

# CloudWatch Log Groups — all groups in the current region with retention.
data "aws_cloudwatch_log_groups" "all" {}

# AWS Config — configuration recorder.
# Recorder is typically named "default"; adjust if the account uses a custom name.
data "aws_config_configuration_recorder" "current" {
  name = "default"
}

# SNS Topics in the current region.
data "aws_sns_topics" "all" {}

###############################################################################
# BILLING AND COST
###############################################################################

# Billing CloudWatch alarms.
# NOTE: AWS billing metrics are emitted to us-east-1 (N. Virginia) regardless
# of the account's primary region.  For a complete billing alarm list, run:
#   aws cloudwatch describe-alarms \
#     --region us-east-1 \
#     --alarm-name-prefix Billing \
#     --query 'MetricAlarms[*].{Name:AlarmName,State:StateValue,Threshold:Threshold}'
# Requires AWS provider >= 5.x.  If data source not found, check provider version.
data "aws_cloudwatch_metric_alarms" "billing" {
  alarm_name_prefix = "Billing"
}

# NOTE: Listing all AWS Budgets is not supported via a Terraform data source.
# Enumerate budgets with:
#   aws budgets describe-budgets --account-id <ACCOUNT_ID> \
#     --query 'Budgets[*].{Name:BudgetName,Type:BudgetType,Limit:BudgetLimit}'
# No data source is included here; this gap is documented in outputs.

# Cost Explorer — 90-day spend grouped by SERVICE.
# PREREQUISITE: Cost Explorer must be activated in the billing console BEFORE
# running this module.  Without activation the data source will error.
#   AWS Console → Billing → Cost Explorer → Enable Cost Explorer
locals {
  # Use DAILY granularity so any valid date range is accepted by the CE API.
  # Approximately 90 days back from plan time.
  ce_start_date = formatdate("YYYY-MM-DD", timeadd(timestamp(), "-2160h"))
  ce_end_date   = formatdate("YYYY-MM-DD", timestamp())
}

data "aws_ce_cost_and_usage" "by_service_90d" {
  time_period {
    start = local.ce_start_date
    end   = local.ce_end_date
  }
  granularity = "DAILY"

  group_by {
    type = "DIMENSION"
    key  = "SERVICE"
  }
}

# Separate query grouped by REGION for data-residency cross-check.
data "aws_ce_cost_and_usage" "by_region_90d" {
  time_period {
    start = local.ce_start_date
    end   = local.ce_end_date
  }
  granularity = "DAILY"

  group_by {
    type = "DIMENSION"
    key  = "REGION"
  }
}

###############################################################################
# COMPLIANCE
###############################################################################

# Security Hub — returns an error if Security Hub is not enabled.
# A plan error here IS a finding — record Security Hub as disabled.
data "aws_securityhub_hub" "current" {}

# KMS — customer-managed keys (CMKs) only.  Excludes AWS-managed keys.
data "aws_kms_keys" "customer_managed" {
  filter {
    name   = "key-manager"
    values = ["CUSTOMER"]
  }
}

data "aws_kms_key" "all" {
  for_each = toset(data.aws_kms_keys.customer_managed.ids)
  key_id   = each.value
}

locals {
  kms_keys_without_rotation = {
    for id, key in data.aws_kms_key.all :
    id => {
      arn         = key.arn
      description = key.description
      key_state   = key.key_state
    }
    if !key.key_rotation_enabled && key.key_state == "Enabled"
  }
}

# Secrets Manager — names and ARNs of all secrets in this account/region.
data "aws_secretsmanager_secrets" "all" {}

###############################################################################
# ORGANISATION
###############################################################################

# Returns organisation details if the account is a member of an AWS Org.
# Returns an error if the account is standalone (no Org).
# A plan error here means this is a standalone account — record accordingly.
data "aws_organizations_organization" "current" {}

locals {
  # Safe evaluation in case account is standalone (data source errors).
  is_management_account = try(
    data.aws_organizations_organization.current.master_account_id == data.aws_caller_identity.current.account_id,
    null
  )

  org_member_account_count = try(
    length(data.aws_organizations_organization.current.accounts),
    0
  )
}

###############################################################################
# CARE SECTOR INTEGRATIONS
###############################################################################

# Lambda functions — list all functions in the current region.
# Requires AWS provider >= 5.34.0.
data "aws_lambda_functions" "all" {}

# Per-function detail — captures runtime, role ARN, and environment variable keys.
# NOTE: Environment variable VALUES are intentionally excluded from outputs
# to avoid capturing secrets in Terraform state.  The keys alone surface
# whether sensitive configuration is passed via env vars (a finding if so).
data "aws_lambda_function" "all" {
  for_each      = toset(data.aws_lambda_functions.all.function_names)
  function_name = each.value
}

locals {
  lambdas_with_env_vars = {
    for name, fn in data.aws_lambda_function.all :
    name => {
      arn              = fn.arn
      runtime          = fn.runtime
      role             = fn.role
      # Keys only — values excluded from state for security.
      env_var_keys     = keys(try(fn.environment[0].variables, {}))
      env_var_count    = length(try(fn.environment[0].variables, {}))
    }
    if length(try(fn.environment[0].variables, {})) > 0
  }

  lambda_summary = {
    total_function_count        = length(data.aws_lambda_functions.all.function_names)
    functions_with_env_vars     = length(local.lambdas_with_env_vars)
  }
}

# EventBridge / CloudWatch Events — rules on the default event bus.
data "aws_cloudwatch_event_rules" "default_bus" {
  event_bus_name = "default"
}
