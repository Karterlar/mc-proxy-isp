# Development and verification

[English](DEVELOPMENT.md) | [简体中文](../DEVELOPMENT.md)

This document covers source version **1.6.11-rc.17**. The project targets Windows x64 and uses an Electron desktop shell, a local Node.js controller, and an HTML/CSS/ES modules frontend.

[README](../../README.md) · [Features](FEATURES.md) · [Architecture](ARCHITECTURE.md) · [Licensing](LICENSING.md) · [Security](../../SECURITY.en.md) · [中文](../DEVELOPMENT.md)

## Start a development session

Use Windows, Node.js **24 LTS**, and pnpm. The license-issuing tools use Node.js's built-in `node:sqlite` module, so Node.js 24 LTS is the development and verification baseline for this public source distribution. Earlier references to Node.js 22.12+ are historical and are no longer the recommended setup. Dependency versions are pinned in [package.json](../../package.json) and [pnpm-lock.yaml](../../pnpm-lock.yaml).

```powershell
pnpm install --frozen-lockfile
pnpm run install:desktop
pnpm dev
```

The explicit installation command prepares the Electron runtime. `pnpm dev` runs `electron . --mock`; demo and real modes use separate data directories and desktop instances. Demo mode lets you explore the interface, state transitions, and error messages. It simulates proxy operation, browser cleanup, system environment changes, and firewall actions.

## Requirements for real connections

```powershell
pnpm start
```

The real desktop startup path checks administrator access. Follow the window's elevation prompt. Starting the application and establishing a connection are separate actions. Prepare the following before connecting:

- An HTTP CONNECT or SOCKS5 ISP proxy, with credentials or an appropriate source-IP allowlist.
- Enrollment details for your own relay, a local VPN configuration, or an external VPN that is already running, depending on the selected route.
- The pinned sing-box **1.14.2** Windows x64 core. The default path is `backend/.cache/core/sing-box-1.14.2-windows-amd64/sing-box.exe`. The relevant runtime and distribution paths also require the matching `libcronet.dll` and license files.
- A local Chrome or Edge installation. The optional fingerprint browser requires a matching runtime manifest and the integrity digests pinned in the source; an ordinary Chromium installation cannot replace it.

Runtime data is stored in local private directories and may include configuration, credentials, browser sessions, and recovery records. Keep generated runtime directories out of version control. For troubleshooting, prefer the application's redacted support report.

## Automated verification

After installing dependencies, start with the minimal regression checks below. They do not require sing-box or browser binaries. These checks use pure logic, mocks, or isolated local services; they do not establish real provider connections or change the actual system network.

```powershell
# Controller orchestration, license client, and signature format
node --test backend/test/local-controller.test.mjs backend/test/license-client.test.mjs backend/test/license-format.test.mjs

# Edition preparation and package-content auditing
pnpm run test:packaging
```

Prepare each suite's required resources before running the full test set. On Windows in particular, tests including `config.test.mjs`, `core-connections-native.test.mjs`, `offline-vpn-chain.test.mjs`, `offline-vpn-chain-native.test.mjs`, `vpn-protocol-core.test.mjs`, and `vpn-yaml.test.mjs` read `backend/.cache/core/sing-box-1.14.2-windows-amd64/sing-box.exe` directly. They fail when the core is missing. Do not assume that the entire backend suite automatically skips native tests.

Some other native tests select executables through `SING_BOX_BIN` or `BROWSER_BIN`. Those optional cases skip only when their corresponding variable is absent. These variables do not replace the hardcoded core path used by the tests listed above. Use local executables whose versions, origins, and digests you have checked. Browser tests use isolated profile directories. Some Windows-specific checks also require PowerShell, system tools, and their own local acceptance resources; read the prerequisites in each test file first.

Once the resources are ready, run the suites that match your verification scope:

```powershell
# Full backend suite, including the pinned core and Windows native tests
node --test backend/test/*.test.mjs

# Desktop lifecycle, IPC, interface state, and licensing integration
pnpm run test:desktop

# Extended licensing regression, including the node:sqlite issuing tools
pnpm run test:licensing

# Real Electron shell with an isolated mock controller
pnpm run desktop:smoke
```

Report the commands and environment you actually used, including passed, failed, and skipped cases. Historical test totals do not establish the current result. Core configuration validation and isolated test chains do not verify real TUN operation, provider networks, or account workflows.

Interface acceptance checks, native fingerprint consistency checks, and building the browser from source each have additional environment requirements. Passing ordinary regression tests does not establish that these checks are complete. Real-machine acceptance should separately cover connection and disconnection, browser egress, DNS and WebRTC, network changes, resume from sleep, upgrades, and recovery.

## Build limits

The project includes build code for unpacked directories, installers, and portable applications. The full distribution workflow validates source, components, fingerprint runtime inventories, and package contents. It requires the pinned sing-box files and their original archive, the matching fingerprint browser built from source, integrity inventories and build receipts, and the historical native acceptance resources expected by the browser tools. The public source preserves these tools, but does not include the complete binaries, private license-issuing data, or the original project's local acceptance environment.

Source preparation, patch checks, standalone algorithm tests, Chromium compilation, and browser acceptance are separate stages. A complete distribution cannot substitute ordinary Chromium for the pinned runtime, or bypass version and integrity checks by generating a receipt alone. Use the following command only after all pinned components and acceptance prerequisites are in place:

```powershell
pnpm run build:developer
```

The Licensed edition requires an explicitly supplied client license configuration containing only trusted public keys:

```powershell
node tools/packaging/build.mjs --edition licensed --license-config <public-config.json> nsis portable
```

Replace `<public-config.json>` with the actual configuration path before running the command. Never put an issuing private key in client configuration. `pnpm run build:licensed` does not supply this required argument by itself.

The core documentation describes the public source distribution; it does not include historical local acceptance materials. A clean clone and the existing scripts do not constitute a complete release build recipe. Before preparing a distribution, review resource inventories, component licenses, reproducibility, clean-machine acceptance, and code signing. The application source remains **UNLICENSED**; see [Licensing](LICENSING.md) for the distinction between public source visibility and permission to use, modify, or redistribute it.

The builder explicitly disables automatic publishing and treats its outputs as unsigned test builds. A package audit establishes content and integrity only within its inspection scope. It does not establish readiness for commercial release or completion of all network security acceptance checks.

## Where to make changes

| Area | Main files |
| --- | --- |
| Desktop startup, permissions, and IPC | [desktop/main.mjs](../../desktop/main.mjs), [desktop/preload.cjs](../../desktop/preload.cjs) |
| Request orchestration and authoritative state | [local-controller.mjs](../../backend/src/local-controller.mjs) |
| Core and connection lifecycle | [proxy-runtime.mjs](../../backend/src/proxy-runtime.mjs) |
| Configuration and TUN routing | [config.mjs](../../backend/src/config.mjs), [routing-policy.mjs](../../backend/src/routing-policy.mjs) |
| Browser and user environments | [browser-session.mjs](../../backend/src/browser-session.mjs), [browser-workspaces.mjs](../../backend/src/browser-workspaces.mjs) |
| Frontend interactions and state display | [app.js](../../frontend/app.js), [workspace-view.js](../../frontend/workspace-view.js) |
| Editions, builds, and audits | [edition.mjs](../../tools/packaging/edition.mjs), [audit.mjs](../../tools/packaging/audit.mjs) |

For changes involving system settings, browser profiles, or recovery records, verify with isolated mocks or temporary directories first, then perform real-machine acceptance within a clearly defined scope. Follow the data-handling and reporting boundaries in [Security](../../SECURITY.en.md).
