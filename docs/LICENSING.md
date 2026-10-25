# 项目许可与双版机制

[English](en/LICENSING.md) | [简体中文](LICENSING.md)

## 源码公开状态

本副本保留 `package.json` 原有的 **UNLICENSED** 标识，没有新增 MIT、Apache 或 GPL 等应用源码许可证。公开可见与授予开源许可是不同事项；应用源码的使用、修改与分发授权需由项目权利人另行明确。

`licenses/` 保存第三方组件的版权、许可及来源说明，各组件保留其自身适用条款。第三方许可不自动为 MC Proxy 应用新增授权；应用授权也不替代第三方组件要求。

## Developer 与 Licensed

| 版本 | 用途 | 应用身份 |
| --- | --- | --- |
| Developer | 本地开发、维护、离线许可签发 | 独立的 Developer 应用 ID 与数据目录 |
| Licensed | 使用设备绑定的签名许可进行客户交付 | 独立的客户版应用 ID 与数据目录 |

默认源码分发配置为 Developer。Licensed 构建必须显式传入**只含受信公钥**的客户端许可配置；公开源码不附带任何现有客户许可、运营签发公钥配置、私钥或签发台账。

```powershell
node tools/packaging/build.mjs --edition licensed --license-config <public-config.json> nsis portable
```

维护端签发工具源代码位于 `tools/licensing/`，桌面签发入口位于 `desktop/licensing-admin.mjs`。工具产生的私钥、客户资料、订单与许可输出应放在私有目录，不能提交到公开仓库。

软件许可控制软件自身的使用，并不提供 ISP、VPN 或 VPS 资源。线路账号、供应商有效期和线路停用仍需要独立管理。请勿把签名许可文件当成不含秘密的连接配置；单文件交付也可能携带完整代理认证资料。

## 升级与兼容

私有部署升级时，应保留原应用身份、客户数据位置和受信公钥。更换签发库会改变信任根，不能假定新密钥可以续签现有客户。此公开副本没有修改原工作目录、现有客户授权或签发库。

构建资源与测试前提见 [开发说明](DEVELOPMENT.md)。发行前应按实际包含的组件检查其许可、源码与通知材料；本仓库不包含预编译交付物。
