# 架构

[English](en/ARCHITECTURE.md) | [简体中文](ARCHITECTURE.md)

源码版本：**1.6.11-rc.17**。[返回 README](../README.md) · [功能说明](FEATURES.md) · [开发与验证](DEVELOPMENT.md) · [许可机制](LICENSING.md)

## 运行结构

```text
Electron 主进程
  ├─ 权限检查、单实例、托盘、安全退出、固定 IPC
  ├─ 本地控制器（127.0.0.1，私有授权）
  │    ├─ 配置与出口验证
  │    ├─ sing-box 连接生命周期 / TUN / 显式代理
  │    ├─ 浏览器进程与独立资料管理
  │    ├─ Windows 环境快照与恢复
  │    ├─ 离线许可与交付事务
  │    └─ 分层诊断与脱敏报告
  └─ 沙箱渲染器（内置 HTML/CSS/ES modules）
       └─ 受限 preload 桥 + 本地控制器请求
```

[desktop/main.mjs](../desktop/main.mjs) 启动控制器和窗口，管理权限、应用身份、单实例、托盘与退出。[local-controller.mjs](../backend/src/local-controller.mjs) 编排用户动作并提供权威状态。前端通过 [controller-client.js](../frontend/controller-client.js) 管理请求，通过 [workspace-view.js](../frontend/workspace-view.js) 推导连接与恢复展示。

渲染器开启 sandbox 与 contextIsolation，禁用 Node 集成；[preload.cjs](../desktop/preload.cjs) 只公开固定能力。窗口关闭会收起到托盘，控制器继续运行。安全退出负责结束受管会话，恢复系统环境和解除遗留网络保护是另外的明确操作。

## 从保存配置到连接就绪

1. [onboarding.mjs](../backend/src/onboarding.mjs) 保存配置与偏好；凭据放在独立私有文件中。
2. [setup-verification.mjs](../backend/src/setup-verification.mjs) 经所选链路请求两个出口来源，检查一致性并记录预期 ISP 出口。
3. [proxy-runtime.mjs](../backend/src/proxy-runtime.mjs) 生成受控核心配置并启动固定核心。导入配置由 [vpn-yaml.mjs](../backend/src/vpn-yaml.mjs) 提取受支持节点，不直接执行导入配置的规则与脚本。
4. HTTP 模式核验本地代理出口；TUN 模式还检查网卡、双栈路由、DNS 与系统默认网络的新建 HTTPS 请求。
5. 控制器根据有效核验状态开放受管浏览器和应用入口。失败时保留分类错误与恢复信息，不能用前端展示状态代替实际核验。

公共流量默认走 ISP。[routing-policy.mjs](../backend/src/routing-policy.mjs) 为智能规则模式加入本地私网 TCP 例外，保留受保护域名与应用的 ISP 路径，并拒绝非 DNS UDP。显式代理模式的覆盖范围由应用是否接入决定。

新持久断网锁当前暂停创建。[network-lock.mjs](../backend/src/network-lock.mjs) 默认提供旧锁兼容检查和恢复；不要将连接阶段的失败处理理解为核心退出后仍有系统级断网保障。

## 浏览器资料与身份

[browser-session.mjs](../backend/src/browser-session.mjs) 识别 Chrome / Edge、构建启动计划、确认受管进程身份并请求正常关闭。默认浏览器是本机 Chrome，使用本项目独立资料，默认保留登录数据。

[browser-workspaces.mjs](../backend/src/browser-workspaces.mjs) 保存命名环境及其 ISP 绑定。各环境具有独立资料目录，浏览器类型在创建后固定；切换时先关闭当前受管环境。归档、替代环境与 [browser-profile-archives.mjs](../backend/src/browser-profile-archives.mjs) 的资料刷新 / 恢复各有明确语义，移除卡片不等于删除资料。

指纹浏览器作为可选运行时，由固定版本、完整性摘要与收据约束。资料和身份种子独立于组件目录，更新组件不应搬迁或重置用户登录资料。身份一致性检查与网络出口检查是不同的证据。

## 环境、恢复与诊断

[environment-manager.mjs](../backend/src/environment-manager.mjs) 保存原始系统环境并管理应用、验证与恢复记录；[environment-profiles.mjs](../backend/src/environment-profiles.mjs) 管理工作 / 日常方案。操作保留逐项结果，失败或漂移不会被当作完整成功。

连接、环境、资料移动和交付导入均有各自的恢复状态；不应通过删除运行目录来处理未完成事务。只有确认归属的进程、路径与系统改动才能进入恢复操作。

[layered-diagnostics.mjs](../backend/src/layered-diagnostics.mjs) 区分观察层次；[support-report.mjs](../backend/src/support-report.mjs) 从固定字段创建脱敏报告，明确未实测项，并由用户保存到本地。原始日志、配置或浏览器资料不应混入可分享报告。

## 许可与发行

[edition.mjs](../tools/packaging/edition.mjs) 生成 Developer / Licensed 分版，各自具有不同应用身份。Developer 包含维护与签发工具；Licensed 只接受显式指定的受信公钥配置，并校验设备绑定的签名许可。

软件许可与 ISP / VPN / VPS 供应商资源是独立关系。资源日期提醒不替代供应商账号检查，软件续期也不会自动开通或续费线路。

[build.mjs](../tools/packaging/build.mjs) 与 [audit.mjs](../tools/packaging/audit.mjs) 管理受控暂存、资源校验与发行审核。完整发行依赖固定核心、源码构建的指纹浏览器、构建收据与历史原生验收资源；完整资源和本地验收环境不随公开源码提供，详见[构建边界](DEVELOPMENT.md#构建边界)。
