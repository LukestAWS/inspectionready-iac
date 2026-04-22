# InspectionReady Systems — Infrastructure as Code

## Purpose
Reusable Terraform modules for AWS governance remediation.
Built from IronCare simulation. Deployed per client engagement.

## Module Sequence
1. identity — IAM password policy, Access Analyzer, cross-account role
2. data-protection — S3 hardening, encryption, Object Lock
3. backup — AWS Backup vault, schedule, retention
4. monitoring — CloudTrail, CloudWatch alarms, metric filters
5. guardduty — GuardDuty detector, S3 protection
6. security-hub — Security Hub standards, findings aggregation

## Deployment
deployments/ironcare — test bed for all modules

## Status
Modules created: 13 April 2026
Identity module: Friday 18 April 2026
