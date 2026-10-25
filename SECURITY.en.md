# Security notes

[English](SECURITY.en.md) | [简体中文](SECURITY.md)

These notes describe the security boundaries and issue-reporting process for the **1.6.11-rc.17** source. They do not guarantee anonymity, account safety, or the absence of leaks.

[README](README.md) · [Architecture](docs/en/ARCHITECTURE.md) · [Development and verification](docs/en/DEVELOPMENT.md) · [Licensing](docs/en/LICENSING.md)

## Local data

Real use produces ISP and VPN credentials, relay enrollment data, offline licenses, browser cookies, identity seeds, environment snapshots, and recovery records. Treat all of these as private. Do not commit them to a repository or attach them to a public issue.

Private signing keys and issuance ledgers belong on the maintenance side. Client builds should contain only trusted public keys. A single-file delivery may contain complete connection credentials, even when its embedded license is signed, and should be transferred privately. Restrictive file permissions do not mean that all local content is encrypted. Protect your device account and backups.

Refreshing a browser profile, archiving it, and deleting it have different effects. Archives and removed environment cards may retain login data and are not evidence of secure erasure. Do not manually delete a profile directory that is in use or recovery records for an operation that has not finished.

## Application boundaries

- The controller listens on a local loopback address and checks private authorization. Temporary control links must also be kept private.
- Electron renderers use sandboxing and context isolation, with Node integration disabled. The preload bridge exposes a fixed set of capabilities.
- Browser shutdown and process recovery check the executable, launch arguments, dedicated profile directory, and process identity. Operations should stop if ownership cannot be established.
- Configuration import accepts only supported nodes and fields. It does not execute a subscription's original DNS configuration, routing rules, or proxy groups.
- Pinned cores and the optional fingerprint runtime are managed through version and integrity constraints. Check component provenance and the applicable licenses as well.

These measures cannot protect against an attacker who already controls the local administrator account, local processes, or the software supply chain.

## What network protection covers

Egress verification checks whether a request's observed exit matches the expected ISP IP. TUN system verification covers newly created requests using the default network path. It does not prove that every application's existing connections, separate proxy configuration, or login flow uses that path.

**Creation of new persistent network locks is currently paused.** Detection and removal of old locks, along with network repair, remain available. Without an independent blocking mechanism, ordinary applications may resume direct connections when the core exits. TUN rejects non-DNS UDP while running, which can affect applications that depend on UDP.

Assess DNS, WebRTC, and fingerprint settings alongside observations from the actual browser. Passing a test only establishes the result for that environment and scope at that time. Network connectivity does not establish successful website authorization. A fingerprint environment cannot guarantee that a website will not recognize you or restrict an account.

Third-party ISP, VPN, and relay providers sit on your traffic path. Choose and manage that trust according to your needs. The current release process targets unsigned test artifacts; it does not establish commercial code signing or completed lifecycle acceptance testing on a clean machine.

## Sharing diagnostics

Prefer the application's **one-click fault report** (一键故障报告). It is generated from a fixed allowlist of fields and excludes raw logs, IP addresses, account credentials, subscription URLs, configurations, browser profiles, and fingerprint seeds. Reports are saved locally by default and are not uploaded automatically.

Raw logs, offline diagnostic directories, screenshots, and manually copied errors can contain a different range of data. Review them before sharing. Do not attach customer configurations, cookies, original license files, or private keys as reproduction material.

## Reporting an issue

For functional problems, a public repository issue can include the source version, Windows version, routing mode, minimal reproduction steps, and redacted error codes. Remove identity and connection details first.

For vulnerabilities involving credential exposure, authorization bypass, arbitrary command execution, or file access, use the repository's private vulnerability reporting feature if it is enabled. If it is unavailable, open an issue without exploit details or secrets and ask the maintainer for a private channel. The project does not currently commit to a fixed response time or a long-term security maintenance period.

## Public test data

[backend/test/relay-tls-fixture.mjs](backend/test/relay-tls-fixture.mjs) and [tools/relay-service/test-fixtures/](tools/relay-service/test-fixtures/) contain fixed, self-signed localhost TLS test material. Some tests also use explicitly synthetic private-key markers, passwords, and subscription tokens to exercise redaction and validation. These are not operational accounts. The test certificates and keys are deliberately public test data and must never be used for real services or license issuance.
