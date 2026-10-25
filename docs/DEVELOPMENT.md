# 开发与验证

[English](en/DEVELOPMENT.md) | [简体中文](DEVELOPMENT.md)

本文对应源码 **1.6.11-rc.17**。项目面向 Windows x64，使用 Electron 桌面壳、本地 Node.js 控制器和原生 HTML/CSS/ES modules 前端。

[返回 README](../README.md) · [功能说明](FEATURES.md) · [架构](ARCHITECTURE.md) · [许可机制](LICENSING.md) · [安全说明](../SECURITY.md)

## 开发启动

准备 Windows、Node.js **24 LTS** 和 pnpm。许可签发工具使用 Node.js 内置的 `node:sqlite`，请以 Node.js 24 LTS 作为公开源码的开发与验证基线；历史的 22.12+ 说明不作为当前环境推荐。依赖版本固定在 [package.json](../package.json) 与 [pnpm-lock.yaml](../pnpm-lock.yaml)。

```powershell
pnpm install --frozen-lockfile
pnpm run install:desktop
pnpm dev
```

显式安装命令准备 Electron 运行时。`pnpm dev` 相当于 `electron . --mock`，演示与真实模式使用隔离的数据和桌面实例。它适合查看完整界面、状态转换和错误反馈，不运行真实代理、浏览器清理、系统环境修改或防火墙操作。

## 真实连接前提

```powershell
pnpm start
```

真实桌面路径会检查管理员权限；根据窗口提示完成提权。启动应用与建立连接是不同操作。请先准备：

- HTTP CONNECT / SOCKS5 ISP 代理，及其认证或入口白名单。
- 所选链路的自建中转注册信息、本地 VPN 配置或已开启的外部 VPN。
- 源码固定的 sing-box **1.14.2** Windows x64 核心。默认查找 `backend/.cache/core/sing-box-1.14.2-windows-amd64/sing-box.exe`；相关运行与发行还依赖对应 `libcronet.dll` 和许可证。
- 本机安装的 Chrome / Edge。可选指纹浏览器需要匹配运行时清单与源码固定的完整性摘要，普通 Chromium 文件不能替代。

运行数据位于本地私有目录，可能包含配置、认证资料、浏览器登录数据和恢复记录。不要将生成的运行目录加入版本控制；排查问题优先使用应用生成的脱敏故障报告。

## 自动化验证

安装依赖后，先运行不要求 sing-box 或浏览器二进制的最小回归。这些测试使用纯逻辑、mock 或隔离的本地服务，不建立真实供应商链路，也不修改实际系统网络：

```powershell
# 控制器编排、许可客户端与签名格式
node --test backend/test/local-controller.test.mjs backend/test/license-client.test.mjs backend/test/license-format.test.mjs

# 发行分版与包内容审核逻辑
pnpm run test:packaging
```

完整测试套件需要先准备各自要求的资源。特别是 Windows 上，`config.test.mjs`、`core-connections-native.test.mjs`、`offline-vpn-chain.test.mjs`、`offline-vpn-chain-native.test.mjs`、`vpn-protocol-core.test.mjs` 与 `vpn-yaml.test.mjs` 等直接读取 `backend/.cache/core/sing-box-1.14.2-windows-amd64/sing-box.exe`；缺少核心会失败，不能假定整个后端套件会自动跳过原生测试。

另一些原生测试由 `SING_BOX_BIN` / `BROWSER_BIN` 显式选择程序，未提供对应变量时才会跳过这些可选用例。这些变量不能替代上述硬编码的核心路径。只使用已核对版本、来源与摘要的本地程序；浏览器测试使用隔离资料目录。部分 Windows 专项还依赖 PowerShell、系统工具和各自的本地验收资源，应先阅读对应测试文件的前提。

准备好所需资源后，再按范围运行：

```powershell
# 完整后端套件，包含固定核心与 Windows 原生测试
node --test backend/test/*.test.mjs

# 桌面生命周期、IPC、界面状态与授权集成
pnpm run test:desktop

# 扩展许可回归，包含使用 node:sqlite 的签发工具
pnpm run test:licensing

# 真实 Electron 壳 + 隔离 mock 控制器
pnpm run desktop:smoke
```

请报告实际运行的命令、环境、通过 / 失败 / 跳过项，不能用历史测试总数替代当前结果。核心配置验证与隔离测试链不等于真实 TUN、供应商网络或账号业务验证。

界面专项、原生指纹一致性与源码浏览器构建具有各自的环境要求，不能从普通回归通过推导为已完成。真实验收应另外覆盖连接与断开、浏览器出口、DNS / WebRTC、换网与睡眠恢复、升级与恢复流程。

## 构建边界

项目包含目录版、安装版和便携版的构建代码。完整发行流程会校验源码、组件、指纹运行时清单和包内容。所需资源包括固定 sing-box 文件及其原始归档、匹配的源码构建指纹浏览器、完整性清单与构建收据，以及浏览器工具要求的历史原生验收资源。公开源码保留相关工具，但不附带完整二进制、私有签发数据或原项目的本地验收环境。

源码准备、补丁检查、独立算法测试和实际 Chromium 编译 / 浏览器验收是不同阶段。完整发行不能用普通 Chromium 替换固定运行时，也不能仅生成一份收据来绕过版本与完整性检查。以下命令须在全部固定组件和验收前提满足后使用：

```powershell
pnpm run build:developer
```

Licensed 版需要明确提供只含受信公钥的客户端许可配置：

```powershell
node tools/packaging/build.mjs --edition licensed --license-config <public-config.json> nsis portable
```

将 `<public-config.json>` 替换为实际配置文件路径后运行；不要将签发私钥放入客户端配置。`pnpm run build:licensed` 本身没有提供这个必需参数。

公开交付说明集中在本目录的四份文档中。它们不包含历史本地验收材料；直接克隆后不能把现有脚本视为完整可发布构建配方。准备发行时，需要审查资源清单、组件许可证、可复现性、干净机验收与代码签名。

构建器显式关闭自动发布，并按未签名测试渠道处理产物。包审核只证明检查范围内的内容与完整性，不代表已经完成商业发布或全部网络安全验收。

## 修改入口

| 任务 | 主要文件 |
| --- | --- |
| 桌面启动、权限与 IPC | [desktop/main.mjs](../desktop/main.mjs)、[desktop/preload.cjs](../desktop/preload.cjs) |
| 请求编排与权威状态 | [local-controller.mjs](../backend/src/local-controller.mjs) |
| 核心与连接生命周期 | [proxy-runtime.mjs](../backend/src/proxy-runtime.mjs) |
| 配置与 TUN 路由 | [config.mjs](../backend/src/config.mjs)、[routing-policy.mjs](../backend/src/routing-policy.mjs) |
| 浏览器与用户环境 | [browser-session.mjs](../backend/src/browser-session.mjs)、[browser-workspaces.mjs](../backend/src/browser-workspaces.mjs) |
| 前端交互与状态展示 | [app.js](../frontend/app.js)、[workspace-view.js](../frontend/workspace-view.js) |
| 分版、构建与审计 | [edition.mjs](../tools/packaging/edition.mjs)、[audit.mjs](../tools/packaging/audit.mjs) |

修改涉及系统、浏览器资料或恢复记录时，先使用隔离 mock / 临时目录验证，随后再做明确范围的实机验收。遵循 [SECURITY.md](../SECURITY.md) 的数据与报告边界。
