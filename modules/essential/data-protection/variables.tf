variable "aws_account_id" {
  description = "12-digit AWS account ID for the client environment"
  type        = string
  validation {
    condition     = can(regex("^\\d{12}$", var.aws_account_id))
    error_message = "aws_account_id must be exactly 12 digits."
  }
}

variable "aws_region" {
  description = "AWS region for the client environment"
  type        = string
  default     = "eu-west-2"
}

variable "client_name" {
  description = "Client name — used in KMS key description and tags"
  type        = string
}

variable "engagement_reference" {
  description = "Engagement reference number — used in KMS key description and tags"
  type        = string
}

variable "patient_bucket_names" {
  description = "Names of existing S3 buckets containing patient data. These buckets receive KMS CMK encryption in Leaf C. Must not include the log bucket."
  type        = list(string)
}

variable "audit_bucket_names" {
  description = "Names of existing S3 buckets requiring Object Lock WORM protection. Buckets MUST have been created with Object Lock enabled at creation time — see Known Limitations in README. Must not include the log bucket."
  type        = list(string)
}

variable "log_bucket_name" {
  description = "Name of the existing S3 bucket used as the server access log destination. Must exist before running Leaf B. Must not appear in patient_bucket_names or audit_bucket_names."
  type        = string
}

variable "object_lock_retention_days" {
  description = "Default retention period in days for Object Lock on audit buckets. Default 2555 = 7 years, aligned with NHS records management requirements."
  type        = number
  default     = 2555
}

variable "kms_deletion_window" {
  description = "KMS key deletion window in days (7–30). Applied when a key is scheduled for deletion. Default 30 = maximum window."
  type        = number
  default     = 30
  validation {
    condition     = var.kms_deletion_window >= 7 && var.kms_deletion_window <= 30
    error_message = "kms_deletion_window must be between 7 and 30 days."
  }
}

variable "enable_object_lock" {
  description = "Set true to apply Object Lock WORM default retention to audit buckets. Audit buckets must have been created with Object Lock enabled. Default true."
  type        = bool
  default     = true
}

variable "enable_kms" {
  description = "Set true to create a KMS CMK and apply SSE-KMS to patient buckets. If false, patient buckets fall back to SSE-S3 (AES256). Default true."
  type        = bool
  default     = true
}
