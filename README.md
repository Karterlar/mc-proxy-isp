# MC Proxy

[English](README.md) | [简体中文](README.zh-CN.md)

**A Windows ISP proxy client for VPN/VPS proxy chains, verified egress, TUN routing, and persistent browser profiles.**

MC Proxy connects your own ISP proxy through a relay VPS, an imported VPN node, or an existing external VPN. It checks the observed exit before opening a managed browser, and brings connection state, browser profiles, environment settings, and diagnostics into one desktop client.

Source version **1.6.11-rc.17** · Windows x64 · Electron · HTML/CSS/JavaScript

[简体中文](README.zh-CN.md) · [Features](docs/en/FEATURES.md) · [Development](docs/en/DEVELOPMENT.md) · [Architecture](docs/en/ARCHITECTURE.md) · [Licensing](docs/en/LICENSING.md) · [Security](SECURITY.en.md)

![MC Proxy desktop preview](docs/assets/desktop-preview.png)

*Demo mode with placeholder connection details; no production credentials.*

## Highlights

- **Verify the ISP exit.** Two independent sources check the exit during setup. Connections must match the saved expected IP before they are reported ready. The provider determines whether the exit stays fixed over time.
- **Choose the entry route.** Use your relay VPS, import supported VPN nodes, or keep an external VPN running. ISP proxies support HTTP CONNECT and SOCKS5; accounts and infrastructure are supplied by you.
- **Choose traffic coverage.** Relay and imported-node routes support global TUN or a TUN policy with private-network exceptions. Explicit proxy mode covers applications configured to use it. External VPN compatibility provides an explicit HTTP proxy only.
- **Keep browser sessions separate.** Google Chrome is the default, with a dedicated profile that retains cookies and site data. Edge and an optional fingerprint browser are also supported. Named environments keep separate profiles and bind to a verified ISP configuration; one managed environment runs at a time.
- **Manage work and daily settings.** Save environment snapshots and manage Windows time zone, language, and regional settings with explicit restoration.
- **Inspect failures locally.** Distinguish proxy, system-network, TLS, and browser observations. Export a redacted support report without automatic upload.
- **Build two editions.** Developer includes maintenance and offline-license administration; Licensed uses signed, device-bound licenses.

```text
Windows -> relay VPS / imported VPN node / external VPN -> your ISP proxy -> website
```

Imported formats include Clash YAML, sing-box JSON, node URIs, single-layer Base64 text, and limited INI / V2Ray configuration. Supported node types include SS, VMess, VLESS, Trojan, Hysteria2, TUIC, HTTP, and SOCKS, subject to supported fields and transports. Original rules, DNS, and proxy groups are not executed; subscriptions are not automatically refreshed.

## Fingerprint browser source

The source includes the optional fingerprint runtime integration, identity/profile lifecycle, native C++ changes, pinned patches, build scripts and browser checks. Prebuilt browser executables, the full upstream Chromium checkout and personal profiles are excluded. See the [source map](docs/en/FINGERPRINT_BROWSER.md) and [native build notes](tools/fingerprint-browser/native-engine/BUILD-WINDOWS.md). Google Chrome remains the default.

## Quick start

On Windows, install Node.js **24 LTS** and pnpm:

```powershell
git clone https://github.com/Karterlar/mc-proxy-isp.git
cd mc-proxy-isp
pnpm install --frozen-lockfile
pnpm run install:desktop
pnpm dev
```

`pnpm dev` uses an isolated mock controller. Network, system changes, cleanup, and firewall operations are simulated; no ISP account is needed.

Real connections use `pnpm start` and require administrator access, valid connection details, and the pinned sing-box core. Full packaging also depends on the matching source-built fingerprint browser, integrity inventories, build receipts, and historical native acceptance resources. The complete binaries and acceptance environment are not included, so a clean clone is not a complete one-command release build. See [development notes](docs/en/DEVELOPMENT.md) for minimal regression commands, full-suite prerequisites, and build limits.

## Limits

This is an unsigned Windows x64 RC source version. Actual provider routes, upgrades, and sustained operation need separate testing. New persistent network locks are currently disabled; existing locks can still be inspected and repaired. Without independent blocking, ordinary applications may return to direct access when the core stops. TUN rejects non-DNS UDP.

Exit checks cover new requests and do not prove that every application's existing connections use the same route. DNS and WebRTC configuration is not a guarantee of leak-free sessions. A fingerprint browser does not guarantee anonymity or prevent account restrictions. Successful HTTPS transport does not establish account access, regional eligibility, subscription validity, or successful model sessions.

## License

The source retains **UNLICENSED** in `package.json`. Public source visibility does not grant an open-source license; obtain the rights holder's permission before use, modification, or redistribution. Third-party components retain their respective licenses; see [licenses](licenses).

Customer configuration, runtime data, browser profiles, and license-signing private keys are excluded from this source distribution.
