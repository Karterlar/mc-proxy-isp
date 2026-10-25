# Optional Chromium source build on Windows

This directory contains the source preparation recipe, native patches and Windows build runner for Chromium **150.0.7871.186**. Normal MC Proxy browser use defaults to the user's installed Google Chrome; this optional component has a separate build and acceptance process.

## Source inputs

`source-manifest.json` records the Chromium archive, exact upstream revisions, dependency hashes, ordered local patches and GN arguments. Its digest is pinned in `build-windows.ps1`. Keep the manifest and referenced patch bytes unchanged unless deliberately reviewing and updating the full build contract.

The public export includes the recipe and local C++ changes, but excludes downloaded source trees, SDKs, toolchains, compiled browsers, private profiles and old machine-specific execution reports. Source preparation, successful compilation, browser acceptance and runtime promotion are distinct stages.

## Preparation

Use Python 3.11+ and inspect the supported arguments:

```powershell
python tools/fingerprint-browser/native-engine/prepare-source.py --help
python tools/fingerprint-browser/native-engine/prepare-source.py
```

The default invocation checks preparation state without starting compilation. Explicit `--prepare` performs downloads, verifies archives and patches, and prepares a source tree. Review its prerequisites first; this is a large native build and is independent of installing the JavaScript dependencies.

```powershell
python tools/fingerprint-browser/native-engine/prepare-source.py --prepare --seven-zip <path-to-7z.exe>
```

Replace the placeholder with your own 7-Zip executable. The recipe also requires its pinned upstream dependencies and a compatible Python environment; follow preparation failures rather than copying another machine's receipts.

## Build runner

The PowerShell runner defaults to a preflight check. Compilation is explicit:

```powershell
./tools/fingerprint-browser/native-engine/build-windows.ps1
./tools/fingerprint-browser/native-engine/build-windows.ps1 -Build -Jobs 4
```

Use the script's `BuildRoot`, `OutRoot`, `VisualStudioRoot`, `WindowsSdkRoot`, `Python` and `VisualStudioVersion` parameters to select your own local tools. Preparation must produce the verified source receipt expected by the runner. Available disk space, SDK and compiler requirements are checked by `resource-preflight.ps1`; a copied status JSON is not a replacement.

## Tests and runtime promotion

The `canvas/` directory includes C++ source and standalone test source alongside the native patch; `identity/` retains pinned baseline input hashes and patch verification tooling. The broader browser self-tests live one directory above this file and require their own local browser / Playwright prerequisites.

`rebind-full-fix-source.py` and `promote-runtime.mjs` are gated integration tools. Runtime promotion requires the expected component inventory, source identity and native/browser acceptance artifacts. The public export does not supply the original machine's historical verification directory, so it is not a clean-clone, one-command recipe for reproducing the previously shipped binary. Review and produce the required evidence before using the promotion path; do not forge a receipt or weaken the checks to admit an unrelated browser.

Chromium 150 remains the version pinned by this source snapshot. The Chromium 155 rebase and strict Canvas extraction restrictions are outside this export's implementation changes. See the repository [development guide](../../../docs/en/DEVELOPMENT.md) and [security notes](../../../SECURITY.en.md) for the application-level boundaries.
