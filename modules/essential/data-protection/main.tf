# =============================================================================
# data-protection module — three-leaf structure
# All resources are applied to EXISTING buckets only. No buckets are created.
#
# Leaf dependency map:
#   Leaf A ──┐
#            ├──> (no cross-leaf dependency)
#   Leaf B ──┤
#            └──> Leaf C depends on Leaf B completing first
#
# Run order: Leaf A and Leaf B can run in parallel. Leaf C runs after Leaf B.
# =============================================================================

# -----------------------------------------------------------------------------
# Locals
# -----------------------------------------------------------------------------

locals {
  # Combined set of all buckets to be hardened in Leaf B.
  all_buckets = toset(concat(var.patient_bucket_names, var.audit_bucket_names))
}

# =============================================================================
# LEAF A — Account-level block public access. No dependencies.
# Prowler pass condition: S3.1
# =============================================================================

resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# =============================================================================
# LEAF B — Per-bucket hardening.
# Input: bucket name list (patient_bucket_names + audit_bucket_names).
# Prowler pass conditions: S3.2, S3.5, S3.9
# NOTE: Leaf C depends on Leaf B completing successfully.
# NOTE: SSE for patient buckets is managed in Leaf C (KMS override).
#       Leaf B applies SSE-S3 to audit buckets only to prevent two
#       aws_s3_bucket_server_side_encryption_configuration resources
#       targeting the same bucket, which Terraform does not permit.
# =============================================================================

resource "aws_s3_bucket_public_access_block" "hardened" {
  for_each = local.all_buckets

  bucket                  = each.key
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "hardened" {
  for_each = local.all_buckets

  bucket = each.key
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "hardened" {
  for_each = local.all_buckets

  bucket        = each.key
  target_bucket = var.log_bucket_name
  target_prefix = "${each.key}/"
}

# SSE-S3 (AES256) for audit buckets only.
# Patient buckets receive SSE-KMS in Leaf C (or SSE-S3 fallback if enable_kms = false).
resource "aws_s3_bucket_server_side_encryption_configuration" "sse_s3_audit" {
  for_each = toset(var.audit_bucket_names)

  bucket = each.key
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = false
  }
}

# HTTPS-only bucket policy.
# Denies all S3 actions where aws:SecureTransport is false.
# WARNING: This policy replaces any existing bucket policy on the target bucket.
# If the bucket already has a policy, retrieve it from initial-state outputs
# and merge before applying. Replacing an existing policy is a known limitation.
resource "aws_s3_bucket_policy" "https_only" {
  for_each = local.all_buckets

  bucket = each.key
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonHTTPS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          "arn:aws:s3:::${each.key}",
          "arn:aws:s3:::${each.key}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.hardened]
}

# =============================================================================
# LEAF C — Compliance controls.
# DEPENDENCY: Leaf B must complete before Leaf C runs.
# Input: patient_bucket_names, audit_bucket_names, KMS key ARN from this leaf.
# Prowler pass conditions: S3.14, S3.17
# =============================================================================

# KMS Customer Managed Key for patient data buckets.
# count = 0 when enable_kms = false (patient buckets fall back to SSE-S3).
resource "aws_kms_key" "patient_data" {
  count = var.enable_kms ? 1 : 0

  description             = "InspectionReady CMK — ${var.client_name} patient data — ${var.engagement_reference}"
  deletion_window_in_days = var.kms_deletion_window
  enable_key_rotation     = true

  tags = {
    Client             = var.client_name
    EngagementRef      = var.engagement_reference
    ManagedBy          = "InspectionReady"
    DataClassification = "PatientData"
  }
}

resource "aws_kms_alias" "patient_data" {
  count = var.enable_kms ? 1 : 0

  name          = "alias/inspectionready-${var.client_name}-patient-data"
  target_key_id = aws_kms_key.patient_data[0].key_id
}

# SSE-KMS override for patient buckets.
# Depends on Leaf B hardening (versioning, logging, public access block, policy)
# completing first before compliance controls are applied.
resource "aws_s3_bucket_server_side_encryption_configuration" "sse_kms_patient" {
  for_each = var.enable_kms ? toset(var.patient_bucket_names) : toset([])

  bucket = each.key
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.patient_data[0].arn
    }
    bucket_key_enabled = true
  }

  depends_on = [
    aws_s3_bucket_public_access_block.hardened,
    aws_s3_bucket_versioning.hardened,
    aws_s3_bucket_logging.hardened,
    aws_s3_bucket_policy.https_only,
  ]
}

# SSE-S3 fallback for patient buckets when enable_kms = false.
# Activates only when KMS is explicitly disabled.
resource "aws_s3_bucket_server_side_encryption_configuration" "sse_s3_patient_fallback" {
  for_each = var.enable_kms ? toset([]) : toset(var.patient_bucket_names)

  bucket = each.key
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = false
  }

  depends_on = [
    aws_s3_bucket_public_access_block.hardened,
    aws_s3_bucket_versioning.hardened,
  ]
}

# Object Lock WORM default retention for audit buckets.
# KNOWN LIMITATION: Object Lock can only be enabled at bucket creation time.
# If an audit bucket was created without Object Lock, this resource will fail
# with an InvalidBucketState error. Document as a Risk Register finding if
# encountered during initial-state review. See README Known Limitations.
resource "aws_s3_bucket_object_lock_configuration" "audit_worm" {
  for_each = var.enable_object_lock ? toset(var.audit_bucket_names) : toset([])

  bucket = each.key
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.object_lock_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.hardened]
}
