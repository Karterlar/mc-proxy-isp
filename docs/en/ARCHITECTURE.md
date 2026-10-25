# Architecture

[English](ARCHITECTURE.md) | [简体中文](../ARCHITECTURE.md)

Source version: **1.6.11-rc.17**. [README](../../README.md) · [Features](FEATURES.md) · [Development and verification](DEVELOPMENT.md) · [Licensing](LICENSING.md) · [中文](../ARCHITECTURE.md)

## Runtime structure

```text
Electron main process
  ├─ Permission checks, single instance, tray, safe exit, defined IPC surface
  ├─ Local controller (127.0.0.1, private authorization)
  │    ├─ Configuration and exit verification
  │    ├─ sing-box connection lifecycle / TUN / explicit proxy
  │    ├─ Browser processes and separate profiles
  │    ├─ Windows environment snapshots and restoration
  │    ├─ Offline licensing and delivery transactions
  │    └─ Layered diagnostics and redacted reports
  └─ Sandboxed renderer (bundled HTML/CSS/ES modules)
       └─ Restricted preload bridge + local controller requests
```

[desktop/main.mjs](../../desktop/main.mjs) starts the controller and windows, and manages permissions, application identity, the single-instance policy, the tray, and exit. [local-controller.mjs](../../backend/src/local-controller.mjs) orchestrates user actions and supplies authoritative state. The frontend manages requests through [controller-client.js](../../frontend/controller-client.js) and derives the connection and recovery display through [workspace-view.js](../../frontend/workspace-view.js).

The renderer enables `sandbox` and `contextIsolation` and disables Node integration. [preload.cjs](../../desktop/preload.cjs) exposes only a defined set of capabilities. Closing a window minimizes it to the tray while the controller keeps running. Safe exit ends managed sessions; restoring the system environment and removing leftover network protection remain separate, explicit actions.

## From saved configuration to a ready connection

1. [onboarding.mjs](../../backend/src/onboarding.mjs) saves configuration and preferences. Credentials are stored in separate private files.
2. [setup-verification.mjs](../../backend/src/setup-verification.mjs) queries two exit-check sources through the selected route, checks their consistency, and records the expected ISP exit.
3. [proxy-runtime.mjs](../../backend/src/proxy-runtime.mjs) generates a controlled core configuration and starts the pinned core. [vpn-yaml.mjs](../../backend/src/vpn-yaml.mjs) extracts supported nodes from imported configuration; it does not directly execute imported rules or scripts.
4. HTTP mode verifies egress through the local proxy. TUN mode also checks the adapter, dual-stack routes, DNS, and new HTTPS requests over the system's default network path.
5. The controller makes managed browser and application launch actions available according to valid verification state. On failure, it retains categorized errors and recovery information. Frontend display state cannot replace actual verification.

Public traffic uses the ISP route by default. In smart-rule mode, [routing-policy.mjs](../../backend/src/routing-policy.mjs) adds TCP exceptions for local private networks, retains the ISP route for protected domains and applications, and rejects non-DNS UDP. Explicit proxy coverage depends on whether an application is configured to use the proxy.

Creation of new persistent network locks is currently paused. By default, [network-lock.mjs](../../backend/src/network-lock.mjs) provides compatibility checks and recovery for existing locks. Failure handling during connection setup does not establish that system-wide blocking remains in effect after the core exits.

## Browser profiles and identity

[browser-session.mjs](../../backend/src/browser-session.mjs) detects Chrome and Edge, prepares launch plans, confirms managed process identity, and requests a normal shutdown. The default browser is the locally installed Chrome, using a profile separate from the user's everyday Chrome profile. Login data is retained by default.

[browser-workspaces.mjs](../../backend/src/browser-workspaces.mjs) stores named environments and their ISP bindings. Each environment has a separate profile directory, and its browser type is fixed when created. Switching environments first closes the current managed environment. Archiving, replacement environments, and the profile refresh and restore operations in [browser-profile-archives.mjs](../../backend/src/browser-profile-archives.mjs) have distinct meanings. Removing an environment card does not delete its profile.

The fingerprint browser is an optional runtime constrained by a pinned version, integrity digests, and receipts. Profiles and identity seeds are stored separately from the component directory. Updating the component should not relocate or reset the user's login data. Identity consistency checks and network exit checks provide different kinds of evidence.

## Environment, recovery, and diagnostics

[environment-manager.mjs](../../backend/src/environment-manager.mjs) saves the original system environment and manages records of changes, verification, and restoration. [environment-profiles.mjs](../../backend/src/environment-profiles.mjs) manages work and everyday profiles. Operations retain per-item results; failures or drift are not reported as complete success.

Connections, environment changes, profile moves, and delivery imports each maintain their own recovery state. Deleting runtime directories is not a recovery method for unfinished transactions. Recovery actions may operate only on processes, paths, and system changes whose ownership has been confirmed.

[layered-diagnostics.mjs](../../backend/src/layered-diagnostics.mjs) distinguishes observation layers. [support-report.mjs](../../backend/src/support-report.mjs) creates a redacted report from a fixed set of fields, identifies checks that were not performed, and lets the user save the report locally. Raw logs, configuration, and browser profiles must remain outside the shareable report.

## Licensing and distribution

[edition.mjs](../../tools/packaging/edition.mjs) prepares Developer and Licensed editions with separate application identities. Developer includes maintenance and license-issuing tools. Licensed accepts only an explicitly specified trusted public-key configuration and validates signed, device-bound licenses.

Software licensing is separate from ISP, VPN, and VPS provider resources. Resource-expiry reminders do not replace provider account checks, and renewing a software license does not activate or renew a connection service. The application source remains **UNLICENSED**; public visibility does not grant permission to use, modify, or redistribute it. Third-party components retain their own applicable licenses. See [Licensing](LICENSING.md).

[build.mjs](../../tools/packaging/build.mjs) and [audit.mjs](../../tools/packaging/audit.mjs) manage controlled staging, resource validation, and distribution auditing. A complete distribution requires the pinned core, the fingerprint browser built from source, build receipts, and historical native acceptance resources. The full resources and local acceptance environment are excluded from the public source distribution. See [Build limits](DEVELOPMENT.md#build-limits).
