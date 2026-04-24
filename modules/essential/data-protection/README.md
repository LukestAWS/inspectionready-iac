# data-protection module

**Stage:** 2 — Essential | **Tier:** Every engagement
**Predecessor:** `modules/initial-state/` must be run first
**Run after:** initial-state outputs reviewed and scope confirmed with client

---

## Purpose

Applies S3 data protection controls to existing client buckets. No buckets are
created. All resources target buckets identified during the initial-state review.

### Regulatory mapping

| Control | Framework | Assertion / Regulation |
|---|---|---|
| Encryption at rest (patient data) | DSPT | Assertion 7 — Personal confidential data |
| Access logging | DSPT | Assertion 7 — Audit trail |
| Object Lock WORM retention | CQC | Regulation 17 — Good governance (records retention) |
| HTTPS-only transport | DSPT | Assertion 7 — Data in transit |
| Block public access | DSPT | Assertion 7 — Unauthorised access prevention |

---

## Leaf structure

This module is divided into three leaves. Each leaf does one thing and produces
one verifiable output.

```
Leaf A — Account-level block public access
  │  No dependencies. Can run in parallel with Leaf B.
  │  Output: aws_s3_account_public_access_block
  │
Leaf B — Per-bucket hardening
  │  Depends on: bucket list input only. Can run in parallel with Leaf A.
  │  Output: public access block, versioning, logging, SSE-S3 (audit buckets),
  │          HTTPS-only policy — applied to every bucket in scope.
  │
  └──> Leaf C — Compliance controls
         Depends on: Leaf B completing successfully.
         Output: KMS CMK, KMS alias, SSE-KMS (patient buckets),
                 Object Lock WORM default retention (audit buckets).
```

**Run order:** Leaf A and Leaf B in parallel → Leaf C after Leaf B.

---

## Pre-requisites

1. **initial-state module must be run first.** Bucket names, versioning status,
   existing policies, and Object Lock status are captured by initial-state.
   Review all outputs before populating variables for this module.

2. **Log bucket must exist before running Leaf B.** The `log_bucket_name`
   variable must reference an existing S3 bucket. Server access logging will
   fail if the target bucket does not exist or is not accessible.

3. **Object Lock must be enabled on audit buckets at bucket creation time.**
   This is an AWS constraint — it cannot be enabled retrospectively on an
   existing bucket. If initial-state reveals audit buckets without Object Lock,
   document this as a Risk Register finding. See Known Limitations below.

---

## Variables

| Variable | Type | Default | Description |
|---|---|---|---|
| `aws_account_id` | string | — | 12-digit AWS account ID (validated) |
| `aws_region` | string | `eu-west-2` | AWS region |
| `client_name` | string | — | Used in KMS key description and tags |
| `engagement_reference` | string | — | Used in KMS key description and tags |
| `patient_bucket_names` | list(string) | — | Buckets with patient data — receive KMS CMK |
| `audit_bucket_names` | list(string) | — | Buckets requiring Object Lock WORM |
| `log_bucket_name` | string | — | Existing bucket for server access logs |
| `object_lock_retention_days` | number | `2555` | Retention days (2555 = 7 years) |
| `kms_deletion_window` | number | `30` | KMS key deletion window, 7–30 days |
| `enable_object_lock` | bool | `true` | Apply Object Lock to audit buckets |
| `enable_kms` | bool | `true` | Create KMS CMK and apply to patient buckets |

---

## Known limitations

### Object Lock cannot be enabled on existing buckets

AWS does not permit Object Lock to be enabled on a bucket after it has been
created. If an audit bucket was created without `object_lock_enabled = true`,
applying this module will fail with `InvalidBucketState`.

**Action when found during initial-state review:**
- Add a finding to the client Risk Register: "Audit bucket [name] was created
  without Object Lock. WORM compliance cannot be applied without recreating the
  bucket. Recommend data migration to a new compliant bucket."
- Set `enable_object_lock = false` for affected buckets until remediation is
  agreed with the client.
- Document in the engagement scope that Object Lock remediation requires
  bucket recreation and is out of scope for this sprint unless agreed.

### Bucket policy replacement

The HTTPS-only bucket policy in Leaf B replaces any existing bucket policy on
each target bucket. If a client bucket already has a resource-based policy,
retrieve it from the initial-state outputs and merge the HTTPS-only deny
statement before applying this module.

---

## Cost impact

| Resource | Cost | Notes |
|---|---|---|
| KMS CMK (`aws_kms_key`) | ~$1.00 USD/month per key | One key created per engagement when `enable_kms = true` |
| KMS API calls | Variable | ~$0.03 per 10,000 requests — typically minimal for care home scale |
| S3 server access logging | Minimal | Log storage billed at standard S3 rates |

**Include in proposal cost statement:** KMS CMK adds approximately £1/month
($1 USD) to the client's AWS bill for the duration of the engagement and beyond.
Advise client this cost continues unless the key is scheduled for deletion post-engagement.

---

## Prowler validation

Run the following checks after `terraform apply` to confirm pass conditions.

| Check ID | Description | Leaf | Expected result |
|---|---|---|---|
| S3.1 | S3 block public access enabled at account level | A | PASS |
| S3.2 | S3 bucket block public access enabled at bucket level | B | PASS — all in-scope buckets |
| S3.5 | S3 bucket denies HTTP requests (HTTPS only) | B | PASS — all in-scope buckets |
| S3.9 | S3 bucket server access logging enabled | B | PASS — all in-scope buckets |
| S3.14 | S3 bucket versioning enabled | B | PASS — all in-scope buckets |
| S3.17 | S3 bucket encrypted with SSE-KMS (CMK) | C | PASS — patient buckets only |

Run Prowler command:
```
prowler aws --service s3 --checks s3_1 s3_2 s3_5 s3_9 s3_14 s3_17
```

---

## Deployment notes

Add to `deployments/[client-name]/main.tf`:

```hcl
module "data_protection" {
  source = "../../modules/essential/data-protection"

  aws_account_id       = var.aws_account_id
  aws_region           = var.aws_region
  client_name          = var.client_name
  engagement_reference = var.engagement_reference

  patient_bucket_names = ["client-patient-records", "client-care-plans"]
  audit_bucket_names   = ["client-audit-logs", "client-dspt-evidence"]
  log_bucket_name      = "client-s3-access-logs"
}
```
