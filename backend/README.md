# MC Proxy backend

The desktop application starts the local controller automatically. For the normal development path, install the root dependencies and use `pnpm dev`; see the [development guide](../docs/DEVELOPMENT.md).

`src/` contains configuration parsing, chain setup, core lifecycle, browser workspaces, environment management, licensing and local diagnostics. `test/` contains isolated tests and native integration tests with separate resource prerequisites.

## Configuration CLI

From the repository root:

```powershell
node backend/src/cli.mjs --help
```

The `init` command creates a new private runtime directory from the placeholder files in `examples/`. Fill it with your own provider configuration before validation. The `render` command emits a private deployment bundle, including `sing-box.json`, `install.sh` and the service template; use a new output directory and review it before deployment.

The files in `deploy/` are templates. A real `sing-box.json` belongs in a generated private deployment bundle, not this source repository. No server, ISP account, credential store or prebuilt core is included.
