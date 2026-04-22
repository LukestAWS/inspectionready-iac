###############################################################################
# InspectionReady Systems — Initial State Capture Module
# outputs.tf
#
# Every data source result is surfaced as a named output.
# Outputs are grouped to match the eight categories in main.tf, plus
# the AUDIT TRAIL section.  Use these outputs as the authoritative
# before-state snapshot for the engagement.
###############################################################################

###############################################################################
# AUDIT TRAIL
###############################################################################

output "audit_trail" {
  description = "Authoritative audit trail for this module execution. Records the caller ARN, execution timestamp, client name, and engagement reference. The captured_at field is the engagement-start timestamp used to anchor the 70 % cost-reduction guarantee baseline period."
  value       = local.audit_trail
}

output "audit_trail_caller_identity" {
  description = "Raw aws_caller_identity data source result. Contains the AWS account ID, caller ARN, and caller user ID of the principal that executed this module."
  value       = data.aws_caller_identity.current
}

output "audit_trail_region" {
  description = "AWS region in which this module was executed, as returned by the aws_region data source."
  value       = data.aws_region.current.name
}

###############################################################################
# IDENTITY
###############################################################################

output "identity_password_policy" {
  description = "Raw IAM account password policy. Surfaces minimum length, complexity requirements, maximum age, reuse prevention, and MFA enforcement settings."
  value       = data.aws_iam_account_password_policy.current
}

output "identity_all_user_names" {
  description = "Flat list of all IAM user names in the account, as returned by aws_iam_users."
  value       = data.aws_iam_users.all.names
}

output "identity_all_user_arns" {
  description = "Flat list of all IAM user ARNs in the account."
  value       = data.aws_iam_users.all.arns
}

output "identity_user_details" {
  description = "Map of IAM user name to full aws_iam_user data source result. Includes path, create date, and tags for each user."
  value       = data.aws_iam_user.all
}

output "identity_user_access_keys" {
  description = "Map of IAM user name to access key metadata (key ID, status, create date). Does NOT include secret key values."
  value       = data.aws_iam_access_keys.all
}

output "identity_access_key_summary" {
  description = "Computed summary per user: count of Active keys, count of Inactive keys, and full key detail list."
  value       = local.users_access_key_summary
}

output "identity_users_with_multiple_active_keys" {
  description = "Map of IAM user name to access-key summary for any user holding more than one Active access key. Multiple active keys is a CIS finding."
  value       = local.users_with_multiple_active_keys
}

output "identity_virtual_mfa_devices" {
  description = "All virtual MFA devices registered in the account, as returned by aws_iam_virtual_mfa_devices. Includes serial number and enable date. Hardware MFA devices are not visible via this data source."
  value       = data.aws_iam_virtual_mfa_devices.all.virtual_mfa_devices
}

output "identity_users_with_virtual_mfa" {
  description = "Set of IAM user names for which a virtual MFA device serial number was found. Derived from the MFA device serial-number naming convention; verify with aws iam list-mfa-devices for hardware MFA coverage."
  value       = local.users_with_virtual_mfa
}

output "identity_users_without_virtual_mfa" {
  description = "Set of IAM user names with no virtual MFA device detected. Does not account for hardware MFA. Used to compute the 'users with console access but no MFA' finding; cross-check with aws iam get-login-profile per user."
  value       = local.users_without_virtual_mfa
}

output "identity_count_users_without_virtual_mfa" {
  description = "Count of IAM users with no virtual MFA device detected. A non-zero value is a CIS Benchmark and NHS DSPT finding requiring immediate remediation."
  value       = local.count_users_without_virtual_mfa
}

output "identity_all_role_names" {
  description = "Flat list of all IAM role names in the account."
  value       = data.aws_iam_roles.all.names
}

output "identity_all_role_arns" {
  description = "Flat list of all IAM role ARNs in the account."
  value       = data.aws_iam_roles.all.arns
}

output "identity_role_details" {
  description = "Map of role name to full aws_iam_role data source result. Includes assume-role policy document, path, create date, max session duration, and tags."
  value       = data.aws_iam_role.all
}

output "identity_roles_heuristic_admin" {
  description = "Map of role name to ARN for roles whose name matches common administrator naming patterns (admin, break-glass, superuser, full-access, poweruser, root). This is a HEURISTIC — confirm actual AdministratorAccess policy attachment with: aws iam list-attached-role-policies --role-name <ROLE>."
  value       = local.roles_heuristic_admin
}

###############################################################################
# DATA
###############################################################################

output "data_s3_bucket_names" {
  description = "List of all S3 bucket names in the account (S3 is a global service; all regions included)."
  value       = data.aws_s3_buckets.all.buckets
}

output "data_s3_bucket_detail" {
  description = "Map of bucket name to aws_s3_bucket data source result. Includes region, ARN, and hosted-zone ID."
  value       = data.aws_s3_bucket.all
}

output "data_s3_public_access_blocks" {
  description = "Map of bucket name to public-access block configuration (block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets)."
  value       = data.aws_s3_bucket_public_access_block.all
}

output "data_s3_versioning" {
  description = "Map of bucket name to versioning configuration. Status is 'Enabled', 'Suspended', or absent."
  value       = data.aws_s3_bucket_versioning.all
}

output "data_s3_logging" {
  description = "Map of bucket name to server access logging configuration. target_bucket will be empty if logging is not enabled."
  value       = data.aws_s3_bucket_logging.all
}

output "data_s3_object_lock" {
  description = "Map of bucket name to object lock configuration. object_lock_enabled is 'Enabled' or 'Disabled'."
  value       = data.aws_s3_bucket_object_lock_configuration.all
}

output "data_s3_buckets_outside_primary_region" {
  description = "Map of bucket name to region for any bucket NOT hosted in the primary engagement region (var.aws_region). Flag for UK GDPR / NHS data-residency review."
  value       = local.buckets_outside_primary_region
}

output "data_s3_buckets_with_public_access_risk" {
  description = "Map of bucket name to per-setting public-access block values for any bucket where one or more public-access block settings is disabled. An empty map means all buckets are fully blocked."
  value       = local.buckets_with_public_access_risk
}

output "data_s3_buckets_without_versioning" {
  description = "Map of bucket name to current versioning status for buckets where versioning is not Enabled."
  value       = local.buckets_without_versioning
}

output "data_s3_buckets_without_logging" {
  description = "Set of bucket names for which server access logging has no target bucket configured."
  value       = local.buckets_without_logging
}

output "data_s3_buckets_without_object_lock" {
  description = "Set of bucket names where S3 Object Lock is not enabled."
  value       = local.buckets_without_object_lock
}

output "data_s3_summary" {
  description = "Aggregate counts for the S3 posture: total buckets, outside-primary-region, without versioning, without logging, without object lock, with public access risk."
  value       = local.s3_summary
}

output "data_rds_instance_identifiers" {
  description = "List of all RDS DB instance identifiers in the current region."
  value       = data.aws_db_instances.all.instance_identifiers
}

output "data_rds_instance_detail" {
  description = "Map of DB instance identifier to full aws_db_instance data source result. Includes engine, version, class, multi-AZ, storage encryption status, and publicly accessible flag."
  value       = data.aws_db_instance.all
}

output "data_rds_unencrypted" {
  description = "Map of DB instance identifier to ARN for any RDS instance where storage encryption is disabled. A non-empty map is a critical finding for NHS DSPT and care-data compliance."
  value       = local.rds_unencrypted
}

output "data_rds_publicly_accessible" {
  description = "Map of DB instance identifier to ARN for any RDS instance where publicly_accessible is true. A non-empty map requires immediate investigation."
  value       = local.rds_publicly_accessible
}

output "data_ebs_volume_ids" {
  description = "Set of all EBS volume IDs in the current region."
  value       = data.aws_ebs_volumes.all.ids
}

output "data_ebs_volume_detail" {
  description = "Map of EBS volume ID to full aws_ebs_volume data source result. Includes encryption status, KMS key ARN, size, type, availability zone, and attachment state."
  value       = data.aws_ebs_volume.all
}

output "data_ebs_unencrypted_volumes" {
  description = "Map of volume ID to detail for any EBS volume that is not encrypted. A non-empty map is a finding requiring remediation before patient or care data is stored."
  value       = local.ebs_unencrypted_volumes
}

###############################################################################
# NETWORK
###############################################################################

output "network_vpc_ids" {
  description = "List of all VPC IDs in the current region."
  value       = data.aws_vpcs.all.ids
}

output "network_vpc_detail" {
  description = "Map of VPC ID to summarised VPC attributes (CIDR, default flag, state, DHCP options ID, tags)."
  value       = local.vpc_summary
}

output "network_default_vpc_exists" {
  description = "Boolean. True if any VPC in the current region is the default VPC. The existence of a default VPC is a CIS AWS Foundations Benchmark finding."
  value       = local.default_vpc_exists
}

output "network_default_vpc_ids" {
  description = "List of VPC IDs that are marked as the default VPC. Should be empty in a hardened account."
  value       = local.default_vpc_ids
}

output "network_open_ingress_sg_ids_ipv4" {
  description = "List of security group IDs that have at least one inbound rule permitting 0.0.0.0/0 (any IPv4). Each ID must be investigated to determine the port/protocol scope."
  value       = data.aws_security_groups.open_ingress_ipv4.ids
}

output "network_open_ingress_sg_ids_ipv6" {
  description = "List of security group IDs that have at least one inbound rule permitting ::/0 (any IPv6). Each ID must be investigated to determine the port/protocol scope."
  value       = data.aws_security_groups.open_ingress_ipv6.ids
}

output "network_open_ingress_sg_ids_combined" {
  description = "Deduplicated set of all security group IDs with unrestricted ingress from the internet (IPv4 or IPv6). This is the primary network-exposure finding set."
  value       = local.open_ingress_sg_ids
}

output "network_vpc_ids_requiring_flow_log_verification" {
  description = "Set of all VPC IDs in the current region. The AWS Terraform provider has no data source for VPC Flow Logs; each VPC in this set must be checked manually: aws ec2 describe-flow-logs --filter Name=resource-id,Values=<VPC_ID>. Any VPC without flow logs is a finding."
  value       = local.vpc_ids_requiring_flow_log_verification
}

###############################################################################
# MONITORING AND LOGGING
###############################################################################

output "monitoring_cloudtrail_service_account" {
  description = "AWS CloudTrail service account ID for the current region. Used in S3 bucket policies to permit CloudTrail log delivery. NOTE: This is NOT a list of trails. Enumerate trails with: aws cloudtrail describe-trails --include-shadow-trails."
  value       = data.aws_cloudtrail_service_account.current.id
}

output "monitoring_guardduty_detector" {
  description = "GuardDuty detector configuration for the current region. Includes detector ID, status, and finding-publishing frequency. A plan error on this output means GuardDuty is disabled — record as a critical finding."
  value       = data.aws_guardduty_detector.current
}

output "monitoring_cloudwatch_log_groups" {
  description = "All CloudWatch Log Groups in the current region, as returned by aws_cloudwatch_log_groups. Includes log group names, ARNs, and retention_in_days. A retention of 0 means logs never expire."
  value       = data.aws_cloudwatch_log_groups.all.log_groups
}

output "monitoring_config_recorder" {
  description = "AWS Config configuration recorder details. Includes recording status, IAM role ARN, and recording group. A plan error means Config is not set up — record as a finding."
  value       = data.aws_config_configuration_recorder.current
}

output "monitoring_sns_topic_arns" {
  description = "List of all SNS topic ARNs in the current region. Used to verify that alarm and notification infrastructure is in place for security and billing events."
  value       = data.aws_sns_topics.all.arns
}

output "monitoring_cloudtrail_note" {
  description = "Operational note for the analyst. CloudTrail trail enumeration is not possible via Terraform data sources. This output documents the required CLI command to complete the CloudTrail section of the assessment."
  value       = "MANUAL STEP REQUIRED: aws cloudtrail describe-trails --include-shadow-trails --query 'trailList[*].{Name:Name,HomeRegion:HomeRegion,MultiRegion:IsMultiRegionTrail,S3Bucket:S3BucketName,LogValidation:LogFileValidationEnabled}'"
}

output "monitoring_access_analyzer_note" {
  description = "Operational note for the analyst. IAM Access Analyzer listing is not possible via Terraform data sources. This output documents the required CLI command."
  value       = "MANUAL STEP REQUIRED: aws accessanalyzer list-analyzers --query 'analyzers[*].{Name:name,Type:type,Status:status,Region:arn}'"
}

###############################################################################
# BILLING AND COST
###############################################################################

output "billing_cloudwatch_metric_alarms" {
  description = "CloudWatch metric alarms with name prefix 'Billing' in the current region. NOTE: Billing alarms live in us-east-1; re-run against that region for complete coverage. An empty list means no billing alarms are configured — a high-risk gap for cost governance."
  value       = data.aws_cloudwatch_metric_alarms.billing
}

output "billing_ce_start_date" {
  description = "ISO 8601 start date for the 90-day Cost Explorer query window. Recorded in state so the query window is reproducible."
  value       = local.ce_start_date
}

output "billing_ce_end_date" {
  description = "ISO 8601 end date for the 90-day Cost Explorer query window."
  value       = local.ce_end_date
}

output "billing_ce_by_service_90d" {
  description = "Cost Explorer results for the 90-day window grouped by AWS SERVICE, DAILY granularity. Each element in results_by_time contains groups with keys (service name) and UnblendedCost metrics. Used to identify the top-cost services prior to optimisation and to baseline the 70 % cost-reduction guarantee."
  value       = data.aws_ce_cost_and_usage.by_service_90d.results_by_time
}

output "billing_ce_by_region_90d" {
  description = "Cost Explorer results for the 90-day window grouped by REGION, DAILY granularity. Used to identify spend in non-primary regions that may indicate shadow IT, misconfiguration, or data-residency violations."
  value       = data.aws_ce_cost_and_usage.by_region_90d.results_by_time
}

output "billing_budgets_note" {
  description = "Operational note for the analyst. AWS Budgets enumeration is not available as a Terraform data source. This output documents the required CLI command."
  value       = "MANUAL STEP REQUIRED: aws budgets describe-budgets --account-id ${var.aws_account_id} --query 'Budgets[*].{Name:BudgetName,Type:BudgetType,Limit:BudgetLimit,ActualSpend:CalculatedSpend.ActualSpend}'"
}

###############################################################################
# COMPLIANCE
###############################################################################

output "compliance_securityhub_hub" {
  description = "Security Hub hub configuration for the current region. Includes hub ARN and auto-enable controls setting. A plan error means Security Hub is disabled — record as a critical finding for NHS DSPT and CQC compliance."
  value       = data.aws_securityhub_hub.current
}

output "compliance_kms_customer_managed_key_ids" {
  description = "List of all customer-managed KMS key IDs in the current region. AWS-managed keys are excluded."
  value       = data.aws_kms_keys.customer_managed.ids
}

output "compliance_kms_key_detail" {
  description = "Map of KMS key ID to full aws_kms_key data source result. Includes ARN, description, key state, deletion window, key usage, and key rotation status."
  value       = data.aws_kms_key.all
}

output "compliance_kms_keys_without_rotation" {
  description = "Map of KMS key ID to detail for any customer-managed KMS key that is in the Enabled state but does NOT have automatic key rotation enabled. Non-empty map is a CIS finding."
  value       = local.kms_keys_without_rotation
}

output "compliance_secretsmanager_secret_arns" {
  description = "List of all Secrets Manager secret ARNs in the current region."
  value       = data.aws_secretsmanager_secrets.all.arns
}

output "compliance_secretsmanager_secret_names" {
  description = "List of all Secrets Manager secret names in the current region. Review to confirm no plaintext credentials exist in Lambda environment variables, EC2 user data, or parameter store instead."
  value       = data.aws_secretsmanager_secrets.all.names
}

###############################################################################
# ORGANISATION
###############################################################################

output "organisation_details" {
  description = "AWS Organizations organisation details. Includes master account ID, ARN, feature set, and policy types. A plan error indicates a standalone account (not in an organisation)."
  value       = try(data.aws_organizations_organization.current, null)
}

output "organisation_is_management_account" {
  description = "Boolean. True if this account is the AWS Organizations management (master) account. Null if the account is standalone. Management accounts have elevated risk and should be assessed with particular care."
  value       = local.is_management_account
}

output "organisation_member_account_count" {
  description = "Count of member accounts in the organisation. Zero means either standalone or the module was run from a member account without sufficient permissions to enumerate the org."
  value       = local.org_member_account_count
}

output "organisation_master_account_id" {
  description = "The AWS account ID of the organisation's management account. Null if standalone."
  value       = try(data.aws_organizations_organization.current.master_account_id, null)
}

###############################################################################
# CARE SECTOR INTEGRATIONS
###############################################################################

output "care_sector_lambda_function_names" {
  description = "List of all Lambda function names in the current region."
  value       = data.aws_lambda_functions.all.function_names
}

output "care_sector_lambda_function_arns" {
  description = "List of all Lambda function ARNs in the current region."
  value       = data.aws_lambda_functions.all.function_arns
}

output "care_sector_lambda_function_detail" {
  description = "Map of function name to full aws_lambda_function data source result. Includes ARN, runtime, IAM role, handler, timeout, memory size, VPC config, and environment variable block. Note: environment variable VALUES are redacted from this module's state by design — only keys are captured in the lambdas_with_env_vars output."
  value       = data.aws_lambda_function.all
}

output "care_sector_lambdas_with_env_vars" {
  description = "Map of function name to summary (ARN, runtime, IAM role, env-var keys, env-var count) for any Lambda function that has one or more environment variables configured. Presence of env vars may indicate hardcoded secrets — each function must be reviewed. Environment variable VALUES are intentionally excluded to prevent secrets capture in Terraform state."
  value       = local.lambdas_with_env_vars
}

output "care_sector_lambda_summary" {
  description = "Aggregate counts: total Lambda functions in region, and how many have environment variables configured."
  value       = local.lambda_summary
}

output "care_sector_eventbridge_rule_arns" {
  description = "List of EventBridge (CloudWatch Events) rule ARNs on the default event bus. Used to identify automated integrations, scheduled jobs, and care-pathway triggers in the account."
  value       = data.aws_cloudwatch_event_rules.default_bus.rule_arns
}

output "care_sector_eventbridge_rule_names" {
  description = "List of EventBridge rule names on the default event bus."
  value       = data.aws_cloudwatch_event_rules.default_bus.rule_names
}
