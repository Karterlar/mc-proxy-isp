# 指纹浏览器源码方案

[English](en/FINGERPRINT_BROWSER.md) | [简体中文](FINGERPRINT_BROWSER.md)

本源码副本保留 **默认 Google Chrome + 可选指纹浏览器** 两条方案。整理操作没有删除指纹能力，也没有将当前集成替换成只打开普通浏览器的占位实现。

## 已包含的内容

| 层次 | 源码位置 | 作用 |
| --- | --- | --- |
| 客户端接入与独立资料 | [browser-session.mjs](../backend/src/browser-session.mjs)、[browser-workspaces.mjs](../backend/src/browser-workspaces.mjs) | 启动、关闭、资料归档、环境选择与身份生命周期 |
| 运行时契约 | [fingerprint-browser-runtime.mjs](../backend/src/fingerprint-browser-runtime.mjs)、[fingerprint-browser-install.mjs](../backend/src/fingerprint-browser-install.mjs) | 固定组件版本、完整性清单、安装与启动约束 |
| 安全基线与浏览器观察 | [fingerprint-browser-security.mjs](../backend/src/fingerprint-browser-security.mjs)、[browser-observation.mjs](../backend/src/browser-observation.mjs) | 显式检查、观察结果与当前会话绑定 |
| 前端选择与资料工具 | [browser-tools.js](../frontend/browser-tools.js) | 默认浏览器选择、指纹资料与观察工具交互 |
| 固定上游来源 | [source-manifest.json](../tools/fingerprint-browser/native-engine/source-manifest.json) | Chromium 150.0.7871.186 的来源、修订、依赖与补丁摘要 |
| 原生身份补丁 | [identity/](../tools/fingerprint-browser/native-engine/identity/) | 身份相关补丁及目标文件校验 |
| Canvas 原生修改 | [canvas/](../tools/fingerprint-browser/native-engine/canvas/) | C++ 实现、补丁、头文件及独立测试源 |
| 构建与原生回归 | [native-engine/](../tools/fingerprint-browser/native-engine/)、[fingerprint-browser/](../tools/fingerprint-browser/) | 源码准备、Windows 构建、完整修正与浏览器验收工具 |

## 为什么没有浏览器 EXE 或完整 Chromium 源码树

这是用于公开仓库的轻量源码副本。预编译浏览器、完整 Chromium 下载树、编译中间文件与个人资料目录体积大且包含运行状态，因此不复制；项目自己的接入代码、原生修改、补丁和固定来源清单均保留。

完整 Chromium 上游源码按清单中的固定版本获取，原生构建步骤见 [BUILD-WINDOWS.md](../tools/fingerprint-browser/native-engine/BUILD-WINDOWS.md)。构建与运行时接入还需要匹配的组件清单、收据和原生/浏览器验收，公开副本不附带原开发机的历史验收环境，不能将普通 Chromium 文件直接冒充已核验组件。

## 当前保留的边界

默认使用本机 Chrome，并保留独立资料；指纹浏览器需要用户选择且准备匹配运行时。身份稳定性与资料隔离不等于无法关联、防封或每次会话零泄漏。

当前源码继续使用 150 系列方案。Chromium 155 升级与严格 Canvas 提取限制仍保持暂停，本次公开整理没有恢复这两项开发。详见 [安全说明](../SECURITY.md)。
