# Cloud Security: Identity, Exposure & Attack Paths

Cloud security revolves around **identities, permissions, configuration, and telemetry** far more than network exploits.

## Frequent findings
- **Publicly exposed storage** — open S3 buckets / Azure Blob containers / GCS. Enumerate ACLs and public policies.
- **Excessive IAM permissions** — wildcards (`*:*`), `iam:PassRole` chains, privilege-escalation paths. Enforce least privilege.
- **Instance metadata (IMDS)** — SSRF against `169.254.169.254` steals instance credentials; require **IMDSv2** (session tokens) on AWS.
- **Unmanaged/orphaned assets** and **configuration drift** vs. IaC baseline.
- **Cross-account trust** and organization-policy gaps; **secrets** in env vars/user-data.
- Ensure **logging is complete and retained** (CloudTrail, Azure Activity/Diagnostic, GCP Cloud Logging) — you can't investigate what wasn't logged.

## Provider building blocks
- **AWS**: IAM roles/policies, GuardDuty, Security Hub, CloudTrail, IAM Access Analyzer, KMS.
- **Azure**: Entra ID, Defender for Cloud, Sentinel, Key Vault, Conditional Access.
- **GCP**: IAM, Security Command Center, Cloud Logging, Cloud KMS.

## Tooling
- Posture/audit: **Prowler**, **ScoutSuite**, Steampipe/CloudQuery (query cloud as data), Wiz / Prisma Cloud / Orca (commercial CSPM).
- IaC scanning: **Checkov**, **tfsec**, Terrascan against Terraform before deploy.
- Authorized offensive: **Pacu** (AWS exploitation framework) within scope.

## Frequent tasks
Detect exposed storage, review over-privileged IAM, find unmanaged assets, investigate suspicious cloud API activity (CloudTrail anomalies), rotate exposed credentials, enforce MFA/Conditional Access, scan containers/serverless, and validate log completeness. Prefer provider docs for current behavior — cloud changes fast.

## References
- Prowler — https://github.com/prowler-cloud/prowler
- AWS IMDSv2 — https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- CIS Benchmarks (cloud) — https://www.cisecurity.org/cis-benchmarks
