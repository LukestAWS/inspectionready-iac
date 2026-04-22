###############################################################################
# InspectionReady Systems — Initial State Capture Module
# variables.tf
###############################################################################

variable "aws_account_id" {
  type        = string
  description = "The 12-digit AWS account ID of the client account under assessment."

  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "aws_account_id must be exactly 12 digits with no hyphens."
  }
}

variable "aws_region" {
  type        = string
  default     = "eu-west-2"
  description = "Primary AWS region for the engagement. All resources discovered outside this region are flagged in module outputs. Defaults to eu-west-2 (London) in line with NHS Digital and UK GDPR data-residency expectations."
}

variable "client_name" {
  type        = string
  description = "Short name of the client organisation (e.g. 'Acme Trust'). Included verbatim in the audit trail output and all engagement metadata. Must match the name recorded in the signed statement of work."
}

variable "engagement_reference" {
  type        = string
  description = "Unique engagement reference code issued by InspectionReady Systems (e.g. 'IR-2026-001'). Stamped into the audit trail output so that every Terraform state snapshot can be correlated with the corresponding engagement record, remediation plan, and 70 % cost-reduction guarantee baseline."
}
