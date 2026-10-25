# Fingerprint browser source and integration

[English](FINGERPRINT_BROWSER.md) | [简体中文](../FINGERPRINT_BROWSER.md)

This source export retains both browser options: **Google Chrome by default, with an optional fingerprint browser**. The export includes the fingerprint integration and native changes; it has not replaced them with a placeholder that merely launches an ordinary browser.

## What is included

| Layer | Source | Purpose |
| --- | --- | --- |
| Client integration and dedicated profiles | [browser-session.mjs](../../backend/src/browser-session.mjs), [browser-workspaces.mjs](../../backend/src/browser-workspaces.mjs) | Launch, shutdown, profile archives, environment selection, and the browser identity lifecycle |
| Runtime contract | [fingerprint-browser-runtime.mjs](../../backend/src/fingerprint-browser-runtime.mjs), [fingerprint-browser-install.mjs](../../backend/src/fingerprint-browser-install.mjs) | Pinned component versions, integrity manifests, installation, and launch requirements |
| Security baseline and browser observations | [fingerprint-browser-security.mjs](../../backend/src/fingerprint-browser-security.mjs), [browser-observation.mjs](../../backend/src/browser-observation.mjs) | Explicit checks and observations tied to the current session |
| Browser selection and profile tools | [browser-tools.js](../../frontend/browser-tools.js) | Default browser selection, fingerprint profiles, and observation controls |
| Pinned upstream sources | [source-manifest.json](../../tools/fingerprint-browser/native-engine/source-manifest.json) | Chromium 150.0.7871.186 sources, revisions, dependencies, and patch digests |
| Native identity patches | [identity/](../../tools/fingerprint-browser/native-engine/identity/) | Identity changes and checks for the files they apply to |
| Native Canvas changes | [canvas/](../../tools/fingerprint-browser/native-engine/canvas/) | C++ implementation, patches, headers, and standalone test sources |
| Build and native regression tools | [native-engine/](../../tools/fingerprint-browser/native-engine/), [fingerprint-browser/](../../tools/fingerprint-browser/) | Source preparation, Windows builds, full correction steps, and browser acceptance tools |

## Why the browser executable and full Chromium tree are absent

This is a lightweight source export for a public repository. Prebuilt browsers, the full Chromium checkout, compilation intermediates, and personal profile directories are large or contain runtime state, so they are excluded. The project's integration code, native modifications, patches, and pinned source manifests are included.

Fetch the upstream Chromium source at the version specified in the manifest, then follow [BUILD-WINDOWS.md](../../tools/fingerprint-browser/native-engine/BUILD-WINDOWS.md). Building and integrating the runtime also requires matching component manifests, receipts, and native and browser acceptance checks. The export does not include the original development machine's historical acceptance environment. An ordinary Chromium build cannot simply be presented as a verified component.

## Current limits

MC Proxy uses the locally installed Chrome by default and keeps a dedicated profile. The fingerprint browser requires an explicit choice and a compatible runtime prepared separately. Stable identities and separate profiles do not guarantee that sessions cannot be correlated, that accounts will avoid restrictions, or that every session is leak-free.

The current source continues to use the Chromium 150 series. The Chromium 155 upgrade and strict Canvas extraction restrictions remain paused; preparing this public export has not resumed either effort. See the [security notes](../../SECURITY.en.md).
