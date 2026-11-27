# Security model and reporting

The control plane, agents and recovery keys stay inside the installation you operate. The storage administrator, virtualization administrator and Vesta administrator each have different access. Use distinct credentials and test recovery after losing access to any one service.

| Boundary | Protection and operator responsibility |
| --- | --- |
| Operators and agents | Use trusted HTTPS and your identity provider for operators. Enroll each agent separately, restrict its namespaces and configure mutual TLS. Limit administrative roles to the people who operate the site. |
| Object storage | Enable client-side encryption before protecting a sensitive VM. The agent encrypts before upload. Protect access to the catalog, installation secret and exported recovery keys separately from the bucket. A compromised source or an administrator holding the recovery keys is inside this trust boundary. |
| Destructive storage changes | Versioning and retained chains help recover from mistakes. Use a separate storage identity and independently enforced retention or replication for ransomware recovery. Test that the recovery reader can reach a clean copy. |
| Software supply | Verify the signed release checksums. Releases include a matching product source tag, third-party notices and an SPDX inventory. Read published advisories for affected versions and mitigations. |

[Backup encryption and key custody](packaging/community/backup-and-recovery.md#protecting-the-backup-in-s3) · [Incident recovery](packaging/community/recovery-incidents.md) · [Security advisories](https://github.com/Insitu-IT/vesta/security/advisories)

## Report a security concern

Open [Vesta’s Security tab on GitHub](https://github.com/Insitu-IT/vesta/security). If **Report a vulnerability** is available, use it to contact the maintainers privately.

If the button is unavailable, select **Private follow-up** in [GitHub Issues](https://github.com/Insitu-IT/vesta/issues/new/choose) and ask a maintainer to arrange a confidential channel. Give only your GitHub handle and the request for private contact. Wait for that channel before sharing affected systems, technical details or attachments.

In the private report, include the Vesta version, the affected component or provider, the behavior you observed, and its impact. Use synthetic data in examples and remove credentials, keys, VM contents and identifying information from logs. Maintainers will follow up privately and coordinate disclosure with you.

## Backup encryption and recovery material

The [encryption guide](packaging/okd/runbooks/encryption-custody.md) describes the data visible in S3, the keys held outside the bucket, and how to protect active restore journals.
