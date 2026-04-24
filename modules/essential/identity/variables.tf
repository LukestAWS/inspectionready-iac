variable "client_name" {
  description = "Short name for the client — used in resource names and tags (e.g. ironcare)"
  type        = string
}

variable "environment" {
  description = "Deployment environment (e.g. prod, staging)"
  type        = string
  default     = "prod"
}

variable "inspectionready_account_id" {
  description = "AWS account ID of InspectionReady Systems — granted permission to assume the cross-account audit role"
  type        = string
}

variable "external_id" {
  description = "External ID for cross-account role assumption — prevents confused deputy attacks. Generate per-client and store securely. Never reuse across clients."
  type        = string
  sensitive   = true
}

variable "tags" {
  description = "Common tags applied to all resources in this module"
  type        = map(string)
  default     = {}
}
