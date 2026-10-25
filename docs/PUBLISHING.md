# 上传公开仓库

[English](en/PUBLISHING.md) | [简体中文](PUBLISHING.md)

此目录是独立筛选的源码副本，没有复制原工作目录的 Git 历史、运行数据、客户交付包或构建缓存。先查看 [README](../README.zh-CN.md)、[开发说明](DEVELOPMENT.md) 和 [许可说明](LICENSING.md)。

## 首次提交

在此源码目录打开终端，使用新的空仓库，不导入原工作目录的历史：

```powershell
git init
git add .
git diff --cached --stat
git status --short
git commit -m "Publish MC Proxy source"
git branch -M main
```

在 GitHub 建立自己的空仓库后，替换下列占位地址，再执行上传：

```powershell
git remote add origin <your-repository-url>
git push -u origin main
```

建议仓库简介：

> Windows proxy workspace with verified ISP egress, multi-hop routing, persistent browser profiles, and local diagnostics.

可选主题：`electron`、`proxy`、`windows`、`tun`、`socks5`、`browser-profiles`、`network-diagnostics`。

## 提交范围

根目录保留标准的 `package.json` 入口，用 `pnpm dev` 演示、`pnpm start` 启动。`tools/` 下的网络修复、构建和测试脚本属于功能源码，不是重复的根启动器。

依赖、核心二进制、完整 Chromium 源码树、编译缓存、测试输出与客户资料均不属于本次源码上传范围。安装依赖和运行测试后，再次检查 `git status`，不要使用强制添加去绕过 `.gitignore`。

固定 TLS 测试证书与私钥仅用于本地测试，其证书名称为 `localhost`；它们是公开测试数据，不能用于部署。生产凭据、签发密钥和订阅地址应继续保存在私有运行目录。

本指南只列出手动发布步骤，不会自动创建远程仓库或上传文件。应用许可仍为 UNLICENSED；若希望正式采用开源许可证，应由项目权利人明确选择后再更新说明。
