# =============================================================================
# Leaf A outputs
# =============================================================================

output "account_public_access_block_status" {
  description = "Account-level S3 public access block configuration. All four settings true confirms S3.1 PASS."
  value = {
    block_public_acls       = aws_s3_account_public_access_block.this.block_public_acls
    block_public_policy     = aws_s3_account_public_access_block.this.block_public_policy
    ignore_public_acls      = aws_s3_account_public_access_block.this.ignore_public_acls
    restrict_public_buckets = aws_s3_account_public_access_block.this.restrict_public_buckets
  }
}

# =============================================================================
# Leaf B outputs
# =============================================================================

output "hardened_bucket_list" {
  description = "All buckets to which Leaf B hardening was applied (public access block, versioning, logging, HTTPS policy)."
  value       = sort(tolist(local.all_buckets))
}

output "buckets_with_versioning" {
  description = "Buckets with versioning enabled. Confirms S3.14 readiness."
  value       = sort([for k, _ in aws_s3_bucket_versioning.hardened : k])
}

output "buckets_with_logging" {
  description = "Buckets with server access logging enabled and their log target. Confirms S3.9 PASS."
  value = {
    for k, v in aws_s3_bucket_logging.hardened : k => {
      target_bucket = v.target_bucket
      target_prefix = v.target_prefix
    }
  }
}

output "buckets_with_https_only" {
  description = "Buckets with HTTPS-only deny policy applied. Confirms S3.5 PASS."
  value       = sort([for k, _ in aws_s3_bucket_policy.https_only : k])
}

# =============================================================================
# Leaf C outputs
# =============================================================================

output "kms_key_arn" {
  description = "ARN of the KMS CMK created for patient data encryption. Empty string if enable_kms = false."
  value       = var.enable_kms ? aws_kms_key.patient_data[0].arn : ""
}

output "kms_key_id" {
  description = "Key ID of the KMS CMK for patient data. Empty string if enable_kms = false."
  value       = var.enable_kms ? aws_kms_key.patient_data[0].key_id : ""
}

output "kms_alias_name" {
  description = "Alias name of the KMS CMK. Empty string if enable_kms = false."
  value       = var.enable_kms ? aws_kms_alias.patient_data[0].name : ""
}

output "patient_buckets_with_cmk" {
  description = "Patient buckets with SSE-KMS (CMK) applied. Confirms S3.17 PASS. Empty list if enable_kms = false."
  value       = var.enable_kms ? sort([for k, _ in aws_s3_bucket_server_side_encryption_configuration.sse_kms_patient : k]) : []
}

output "audit_buckets_with_object_lock" {
  description = "Audit buckets with Object Lock WORM default retention applied. Empty list if enable_object_lock = false."
  value       = var.enable_object_lock ? sort([for k, _ in aws_s3_bucket_object_lock_configuration.audit_worm : k]) : []
}

output "object_lock_retention_days_applied" {
  description = "Object Lock retention period in days applied to audit buckets. 0 if enable_object_lock = false."
  value       = var.enable_object_lock ? var.object_lock_retention_days : 0
}

# =============================================================================
# Engagement metadata
# =============================================================================

output "client_name" {
  description = "Client name from engagement context."
  value       = var.client_name
}

output "engagement_reference" {
  description = "Engagement reference from engagement context."
  value       = var.engagement_reference
}

output "module_applied_timestamp" {
  description = "Timestamp when this module was last applied. Use for evidence vault records."
  value       = timestamp()
}
