# Publishing the source repository

[English](PUBLISHING.md) | [简体中文](../PUBLISHING.md)

This directory is a separately selected source export. It excludes the original working directory's Git history, runtime data, customer delivery packages, and build caches. Read the [README](../../README.md), [development guide](DEVELOPMENT.md), and [licensing guide](LICENSING.md) first.

## Make the first commit

Open a terminal in this source directory. Start with a new, empty repository and do not import the original working directory's history:

```powershell
git init
git add .
git diff --cached --stat
git status --short
git commit -m "Publish MC Proxy source"
git branch -M main
```

Create your own empty repository on GitHub, replace the placeholder below with its URL, and push:

```powershell
git remote add origin <your-repository-url>
git push -u origin main
```

Suggested repository description:

> Windows proxy workspace with verified ISP egress, multi-hop routing, persistent browser profiles, and local diagnostics.

Optional topics: `electron`, `proxy`, `windows`, `tun`, `socks5`, `browser-profiles`, `network-diagnostics`.

## Review what you are committing

The root `package.json` is the standard entry point: use `pnpm dev` for a demo or `pnpm start` to start the application. The network repair, build, and test scripts under `tools/` are functional source code, not duplicate launchers.

Dependencies, core binaries, the full Chromium source tree, compilation caches, test outputs, and customer data are excluded from this source export. After installing dependencies or running tests, check `git status` again. Do not use forced adds to bypass `.gitignore`.

The fixed TLS certificates and private keys are **public test data** for local tests, with localhost certificates. They must never be used for deployment. Keep production credentials, signing keys, and subscription URLs in private runtime directories.

Preparing this source export does not itself create a remote repository or upload files. The application remains `UNLICENSED`; adopting an open-source license requires an explicit choice by the project's rights holder and corresponding updates to the documentation.
