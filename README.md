# inspectionready-iac: Terraform modules for AWS governance remediation (lab project)

## Purpose
Reusable Terraform modules for AWS governance remediation.
Written against IronCare, a simulated healthcare environment I built in my own AWS account. This was a first draft: the read-only capture later moved to a Python engine, and fixes were applied via CLI and console. It was never deployed for a client.

## Module Sequence
1. identity — IAM password policy, Access Analyzer, cross-account role
2. data-protection — S3 hardening, encryption, Object Lock
3. backup — AWS Backup vault, schedule, retention
4. monitoring — CloudTrail, CloudWatch alarms, metric filters
5. guardduty — GuardDuty detector, S3 protection
6. security-hub — Security Hub standards, findings aggregation

## Test bed
deployments/ironcare: wires the modules together for the IronCare simulation (written, not applied)

## Status
Modules created: 13 April 2026
Identity module: Friday 18 April 2026
