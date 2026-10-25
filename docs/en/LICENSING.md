# Licensing and distribution editions

[English](LICENSING.md) | [简体中文](../LICENSING.md)

## Source availability

This export retains the existing **`UNLICENSED`** designation in `package.json`. It does not add an MIT, Apache, GPL, or other license for the application source. Making source publicly visible does not grant an open-source license. Permission to use, modify, or distribute the application source must be established separately by the project's rights holder.

The [licenses directory](../../licenses/) contains third-party copyright notices, licenses, and provenance information. Each component remains subject to its own terms. Those licenses do not automatically grant rights to the MC Proxy application, and an application license does not replace third-party obligations.

## Developer and Licensed editions

| Edition | Purpose | Application identity |
| --- | --- | --- |
| Developer | Local development, maintenance, and offline license issuance | A dedicated Developer application ID and data directory |
| Licensed | Customer distribution using signed, device-bound licenses | A separate customer-edition application ID and data directory |

The source distribution defaults to Developer. A Licensed build requires an explicitly supplied client license configuration containing **trusted public keys only**. This public source export includes no existing customer licenses, operational issuer public-key configuration, private signing keys, or issuance ledger.

Run this command from the repository root:

```powershell
node tools/packaging/build.mjs --edition licensed --license-config <public-config.json> nsis portable
```

The maintenance tools for issuing licenses are in [tools/licensing/](../../tools/licensing/), with a desktop entry point in [licensing-admin.mjs](../../desktop/licensing-admin.mjs). Keep any generated private keys, customer records, orders, and license outputs in private directories. Do not commit them to a public repository.

Software licenses control use of the application itself. They do not provide ISP, VPN, or VPS services; provider accounts, service expiry, and connection deactivation require separate management. A signed license file is not necessarily a connection configuration free of secrets. A single-file delivery can contain complete proxy credentials and must be handled accordingly.

## Upgrades and compatibility

When upgrading a private deployment, preserve its application identity, customer data location, and trusted public keys. Replacing the issuance store changes the trust root; do not assume that new keys can renew existing customers' licenses. Preparing this export did not change the original working directory, existing customer authorizations, or issuance store.

See the [development guide](DEVELOPMENT.md) for build resources and test prerequisites. Before distributing a build, check the licenses, source requirements, and notices for the components it actually includes. This repository contains no prebuilt distribution packages.
