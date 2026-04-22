output "access_analyzer_arn" {
  description = "ARN of the IAM Access Analyzer"
  value       = aws_accessanalyzer_analyzer.this.arn
}

output "access_analyzer_id" {
  description = "ID of the IAM Access Analyzer"
  value       = aws_accessanalyzer_analyzer.this.id
}

output "cross_account_role_arn" {
  description = "ARN of the InspectionReady cross-account audit role — provide this to InspectionReady Systems to complete onboarding"
  value       = aws_iam_role.cross_account_audit.arn
}

output "cross_account_role_name" {
  description = "Name of the InspectionReady cross-account audit role"
  value       = aws_iam_role.cross_account_audit.name
}
