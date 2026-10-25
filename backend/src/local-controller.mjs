import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { probe, requestViaProxy, sanitizeProbeFailure } from './probe.mjs';
import { probeSystemExit, directHttpsRequest } from './system-network-probe.mjs';
import { compatibilityRoutes } from './compatibility-network.mjs';
import { createImportedVpnStore } from './imported-vpn-store.mjs';
import { createImportedNodeScreening } from './imported-node-shortlist.mjs';
import { createVpnSubscriptionManager } from './vpn-subscription.mjs';
import { createDiagnosticShareSummary } from './diagnostic-summary.mjs';
import { createServiceReminderManager } from './service-reminders.mjs';
import { createSupportReport } from './support-report.mjs';
import { parseCustomerDelivery, CUSTOMER_DELIVERY_MAX_BYTES } from './customer-delivery.mjs';
import { createCustomerDeliveryImporter } from './customer-delivery-import.mjs';
import { proxyCapabilities } from './proxy-capabilities.mjs';
import { createProxyRuntime } from './proxy-runtime.mjs';
import { createApplicationProxy } from './application-proxy.mjs';
import { createBrowserManager } from './browser-session.mjs';
import { createBrowserWorkspaceManager, BROWSER_WORKSPACE_SERVICES, workspaceBrowser, validBrowserWorkspaceId } from './browser-workspaces.mjs';
import { BROWSER_PROFILE_ERROR_MESSAGES } from './browser-profile-archives.mjs';
import { createBrowserObservation } from './browser-observation.mjs';
import { buildLayeredDiagnosis } from './layered-diagnostics.mjs';
import { prepareFingerprintBrowser, prepareFingerprintBrowserFromBundle } from './fingerprint-browser-install.mjs';
import { FINGERPRINT_BROWSER_INSTALL_DIRECTORY, FINGERPRINT_BROWSER_RELEASE } from './fingerprint-browser-runtime.mjs';
import { createFingerprintSecurityCheck } from './fingerprint-browser-security.mjs';
import { createNetworkReport, CONNECTIVITY_SOURCES, equalIp, requestExitGeography, verifiedExitGeography } from './network-report.mjs';
import { createEnvironmentManager } from './environment-manager.mjs';
import { localeForGeo } from './environment-regions.mjs';
import { createClaudeCleanupManager } from './claude-cleanup.mjs';
import { loadSecrets, validateVpnProxy, validateTransportMode } from './config.mjs';
import { createOnboardingManager } from './onboarding.mjs';
import { createSetupVerifier } from './setup-verification.mjs';
import { sanitizeSetupDiagnostic } from './setup-diagnostic.mjs';
import { createQualityReportStore } from './quality-report.mjs';
import { createRelayManager } from './relay-client.mjs';
import { exportChainDiagnostics } from './diagnostics-export.mjs';
import { sanitizeNetworkLockDiagnostic } from './windows-network-lock.mjs';
import { sanitizeEnvironmentDiagnostic } from './windows-environment.mjs';
import { createLicenseClient, LICENSE_ERROR_MESSAGES } from './license-client.mjs';

const backendRoot = fileURLToPath(new URL('../', import.meta.url));
const frontendRoot = path.resolve(backendRoot, '../frontend');
const PLAN_TTL = 5 * 60_000;
const EXIT_TTL = 90_000;
const VPN_LATENCY_TTL = 5 * 60_000;
// A failed observation is not evidence that a still-owned route has vanished.
// Keep its original proof deadline; only a successful probe can renew it.
const OBSERVATION_FAILURES = new Set(['PROXY_TIMEOUT', 'PROXY_CONNECT_REJECTED', 'PROXY_UNREACHABLE', 'PROXY_CLOSED', 'PROXY_RESPONSE_INVALID',
  'PROBE_TIMEOUT', 'PROBE_TLS_OR_SOCKET_FAILED', 'PROBE_HTTP_STATUS', 'PROBE_REQUEST_FAILED', 'PROBE_RESPONSE_FAILED', 'PROBE_RESPONSE_TOO_LARGE', 'PROBE_IP_INVALID',
  'SYSTEM_DNS_FAILED', 'SYSTEM_NETWORK_TIMEOUT', 'SYSTEM_TLS_FAILED', 'SYSTEM_NETWORK_UNREACHABLE', 'SYSTEM_RESPONSE_INVALID', 'SYSTEM_HTTP_STATUS',
  'PROCESS_QUERY_FAILED', 'TUN_STATE_UNAVAILABLE']);
const MAX_PLANS = 64;
const APPLICATION_TARGETS = Object.freeze({ claude: ['https://api.anthropic.com/', 'https://claude.ai/'], codex: ['https://api.openai.com/', 'https://auth.openai.com/'], browser: ['https://ping0.cc/', 'https://www.cloudflare.com/'] });
const THIRD_PARTY = CONNECTIVITY_SOURCES;
const error = (code, message, status = 409) => Object.assign(new Error(message), { code, status });
const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const timestamp = () => new Date().toISOString();
const isCompatibilityMode = mode => ['vpn-compat', 'vpn-import'].includes(mode);
const success = data => ({ ok: true, data });
const ERROR_MESSAGES = {
  WORKSPACE_BINDING_INVALID: '工作区缺少有效的 ISP 绑定，请先核验并保存配置。',
  WORKSPACE_BINDING_MISMATCH: '当前 ISP 与此工作区不一致，请切回原出口或明确重新绑定。',
  WORKSPACE_ID_INVALID: '工作区标识无效，请刷新列表后重试。',
  WORKSPACE_INPUT_INVALID: '工作区包含无效选项，请检查输入。',
  WORKSPACE_LIMIT_REACHED: '用户环境数量已达上限（24 个活动、96 条总记录），请先整理归档记录。',
  WORKSPACE_IDENTITY_INVALID: '用户环境身份设置无效，请检查语言、时区与图形选项。',
  WORKSPACE_ARCHIVED: '此用户环境已归档，请先恢复后再打开。',
  WORKSPACE_OBSERVATION_TARGET_REQUIRED: '请先打开对应用户环境，再检测或生成检测链接。',
  WORKSPACE_NAME_INVALID: '工作区名称需要 1–40 个字符。',
  WORKSPACE_NOT_FOUND: '工作区已不存在，请刷新列表。',
  WORKSPACE_PATH_INVALID: '工作区路径不安全，原浏览器资料保留。',
  WORKSPACE_SERVICES_INVALID: '请至少选择一个支持的网站，不要重复选择。',
  WORKSPACE_STATE_INVALID: '工作区索引无法读取，请保留资料后检查。',
  WORKSPACE_ACTIVE: '请先正常结束此工作区，再修改或移除卡片。',
  WORKSPACE_INVALID: '工作区启动选项无效。',
  WORKSPACE_SWITCH_CONFIRM_REQUIRED: '请确认先正常关闭当前浏览器，再切换工作区。',
  DELIVERY_INVALID: '交付文件格式无效，请重新选择原始 .mcproxy.json 文件。',
  DELIVERY_ISP_INVALID: '交付文件的 ISP 地址、端口或凭据无效。',
  DELIVERY_VPN_INVALID: '交付文件中没有有效且受支持的 VPN 节点。',
  DELIVERY_SIZE_INVALID: '交付文件超过 1.5 MiB 上限，请维护者精简配置后重新制作。',
  DELIVERY_MODE_INVALID: '交付模式与包含的配置不一致。',
  DELIVERY_MODE_UNSUPPORTED: '当前单文件导入支持 VPN 配置 → ISP；其他方式请使用原有配置入口。',
  DELIVERY_LICENSE_INVALID: '交付文件中的签名许可无效，请维护者按原流程重新签发。',
  DELIVERY_LICENSE_INACTIVE: '此许可已到期或不可用，请维护者重新签发有效许可。',
  DELIVERY_DEVICE_INVALID: '无法确认本机设备身份，请先在授权页面生成设备申请。',
  DELIVERY_REMINDERS_INVALID: '交付文件中的资源提醒日期无效。',
  DELIVERY_PATH_INVALID: '交付不能写入外部、关联或受保护的配置路径；原有配置入口仍可使用。',
  DELIVERY_STATE_INVALID: '本地配置记录异常，请保留原文件后检查。',
  DELIVERY_RECOVERY_REQUIRED: '交付提交或恢复尚未完成，请重新启动客户端恢复；保留原始恢复记录。',
  DELIVERY_CONFLICT: '准备交付期间本地配置已变化，原记录保留，请刷新后重新导入。',
  DELIVERY_BUSY: '交付正在处理中，请等待完成。',
  DELIVERY_VERIFICATION_FAILED: 'VPN 到 ISP 的完整链路未通过验证，原配置保留。',
  DELIVERY_VERIFICATION_MOCKED: '模拟检查不能用于实际交付，原配置保留。',
  REMINDERS_PATH_INVALID: '提醒存储路径不安全，原有连接和授权保持不变。',
  REMINDERS_STATE_INVALID: '提醒记录无法读取，请保留原记录后检查。',
  REMINDERS_INPUT_INVALID: '请先保存对应线路，再选择有效的提醒日期。',
  REMINDERS_CONFLICT: '提醒已被其他操作更新，请刷新后重试。',
  REMINDERS_WRITE_FAILED: '提醒未能保存，请检查本地目录权限。',
  BROWSER_FINGERPRINT_NOT_INSTALLED: '指纹浏览器组件尚未准备，请在应用接入中准备引擎。',
  BROWSER_FINGERPRINT_BUNDLE_REQUIRED: '指纹浏览器需要随版本提供的新内核组件，请使用完整版本；Chrome 仍可使用，原资料保留。',
  BROWSER_FINGERPRINT_BINARY_CHANGED: '浏览器程序与固定摘要不符，已拒绝执行，请重新准备组件。',
  BROWSER_FINGERPRINT_FILES_CHANGED: '浏览器资源完整性校验失败，已拒绝执行。',
  BROWSER_FINGERPRINT_INVENTORY_INVALID: '浏览器组件清单无效，原资料与连接保持原样。',
  BROWSER_FINGERPRINT_ARCH_INVALID: '浏览器组件架构不匹配，请使用受支持的 Windows x64 组件。',
  BROWSER_FINGERPRINT_PLATFORM_UNSUPPORTED: '此浏览器组件暂只支持 Windows x64。',
  BROWSER_FINGERPRINT_PLATFORM_UNAVAILABLE: '无法读取 Windows 浏览器平台版本，请重试；原身份与资料保留。',
  BROWSER_OBSERVATION_RESTART_REQUIRED: '此窗口尚未绑定本机检测端口，请正常关闭后从 MC Proxy 重新打开，再检测。',
  BROWSER_FINGERPRINT_PATH_UNSAFE: '浏览器组件路径包含链接或不安全位置，已拒绝操作。',
  BROWSER_FINGERPRINT_PATH_MANAGED: '指纹浏览器只使用经过固定摘要校验的专用组件。',
  BROWSER_FINGERPRINT_SEED_INVALID: '指纹种子格式无效，原资料保持不变。',
  BROWSER_FINGERPRINT_SEED_CHANGED: '资料空间种子已变更，请重新生成启动计划。',
  BROWSER_FINGERPRINT_STATE_INVALID: '资料空间的指纹记录异常，原记录保持不变。',
  BROWSER_FINGERPRINT_TIMEZONE_INVALID: '请选择有效的浏览器时区。',
  BROWSER_FINGERPRINT_GRAPHICS_INVALID: '浏览器图形设置无效。',
  BROWSER_FINGERPRINT_FRESH_ROTATION_UNSUPPORTED: '纯净空间本身使用新身份；轮换请使用保留资料模式，当前窗口保持运行。',
  OBSERVATION_CONTEXT_INVALID: '浏览器检测缺少当前已核验出口或有效会话，请重新连接后检测。',
  OBSERVATION_SESSION_CHANGED: '检测会话的线路已变化，请重新生成检测页面。',
  OBSERVATION_SESSION_EXPIRED: '浏览器检测链接已失效，请在当前线路重新检测。',
  CONNECTION_CANCELED: '连接已取消，正在清理受管会话。',
  CONNECTION_IN_PROGRESS: '连接或取消正在进行，请等待当前会话清理完成。',
  CORE_TRAFFIC_GATE_FAILED: '未能确认暂停转发；TUN 保持运行，请查看诊断或明确结束连接。',
  ...LICENSE_ERROR_MESSAGES,
  ...BROWSER_PROFILE_ERROR_MESSAGES,
  BROWSER_PROFILE_SCOPE_MISMATCH: '当前运行的浏览器或用户环境与所选资料不一致。请先正常关闭当前窗口，再刷新所选资料。',
  BROWSER_PROFILE_PREFERENCES_FAILED: '新资料已准备，旧资料仍保留，但保留资料偏好尚未保存。请重试，或在会话偏好关闭“每次开启纯净空间”。',
  NETWORK_RECHECK_REQUIRED: '网络发生变化，当前出口租约已撤销；请等待核验或重新连接',
  VPN_SUBSCRIPTION_URL_INVALID: '订阅地址必须是公开 HTTPS 地址，请检查输入',
  VPN_SUBSCRIPTION_PROXY_REQUIRED: '请先用本地配置建立并核验链路，再通过该链路更新订阅',
  VPN_SUBSCRIPTION_TIMEOUT: '订阅更新超时，原配置已保留',
  VPN_SUBSCRIPTION_HTTP_STATUS: '订阅服务器拒绝请求或要求跳转，原配置已保留',
  VPN_SUBSCRIPTION_RESPONSE_INVALID: '订阅内容格式异常，原配置已保留',
  VPN_SUBSCRIPTION_TOO_LARGE: '订阅超过 1 MiB 上限，原配置已保留',
  VPN_SUBSCRIPTION_REQUEST_FAILED: '订阅无法经当前核验链路下载，原配置已保留',
  VPN_SUBSCRIPTION_ROUTE_CHANGED: '订阅下载期间链路发生变化，原配置已保留',
  CORE_API_UNAVAILABLE: '受管核心连接记录暂时不可用，请重新连接或查看客户端日志',
  CORE_API_AUTH_FAILED: '核心观测接口身份校验失败，未读取连接记录',
  CORE_API_RESPONSE_INVALID: '核心观测响应异常，未显示未核验的记录',
  CORE_API_TIMEOUT: '读取核心连接记录超时，当前网络状态保持原样',
  FAKE_IP_CACHE_UNAVAILABLE: 'Fake-IP 映射记录缺失或不安全，未自动重建，请查看恢复说明',
  FAKEIP_CACHE_RECOVERY_REQUIRED: '上次核心未正常关闭，Fake-IP 映射需要恢复；请先关闭受影响的浏览器和应用，再执行明确的缓存恢复',
  FAKEIP_CACHE_CONFIRM_REQUIRED: '映射恢复需要确认已关闭受影响的应用，原记录保持原样',
  FAKEIP_CACHE_RECOVERY_IN_PROGRESS: '映射归档尚未完成，请保留恢复记录并重试明确的映射恢复',
  FAKEIP_CACHE_RECOVERY_FAILED: '映射恢复未完成，原记录已保留，请查看日志后重试',
  ROUTING_POLICY_INVALID: 'TUN 路由策略或受信应用路径无效，未启动核心',
  CORE_VERSION_INVALID: '代理核心版本不符合固定兼容版本，未启动链路，请更新安装包',
  CORE_CONSOLE_CLOSE_FAILED: '核心未能正常关闭，映射记录已保留，下一次连接前需要检查恢复',
  CORE_CONSOLE_START_FAILED: '核心私有进程启动失败，请查看客户端日志后重试',
  CORE_CONSOLE_IDENTITY_FAILED: '无法确认核心进程身份，未向未知进程发送关闭信号',
  CORE_CONSOLE_UNAVAILABLE: '核心私有控制台不可用，未将映射标记为正常保存',
  CORE_CONSOLE_NOT_PRIVATE: '核心控制台包含其他进程，未向共享控制台发送关闭信号',
  CORE_CONSOLE_CLOSE_TIMEOUT: '核心正常关闭超时，映射恢复记录已保留',
  RELAY_NOT_CONFIGURED: '尚未配置中转入口，请先导入正式中转注册文件',
  RELAY_ENROLLMENT_INVALID: '中转注册文件、证书身份或指纹无效',
  RELAY_PATH_INVALID: '中转凭据路径异常，操作已拒绝',
  RELAY_STORAGE_FAILED: '中转注册文件未能安全读取或保存，请检查私有目录权限',
  RELAY_TIMEOUT: '中转服务器响应超时，请检查直连网络和入口状态',
  RELAY_TLS_FAILED: '中转证书验证失败，未继续发送账号信息',
  RELAY_UNREACHABLE: '无法直连中转服务器，请检查网络和服务器状态',
  RELAY_RESPONSE_INVALID: '中转服务器响应不符合协议，未继续连接',
  RELAY_AUTH_FAILED: '中转账号认证失败或已停用，请联系管理员核验注册文件和账号状态',
  RELAY_DISABLED: '中转账号已停用或没有执行此操作的权限',
  RELAY_IN_USE: '中转仍有活动连接，请先结束代理会话再修改 ISP',
  RELAY_BINDING_CONFLICT: '中转绑定已被其他操作修改，未覆盖现有设置',
  RELAY_BINDING_MISMATCH: '中转绑定与保存的 ISP 不一致，请重新保存并验证 ISP',
  RELAY_CONFIGURATION_CHANGED: '中转注册信息与保存的链路不一致，请重新保存并验证 ISP',
  RELAY_ROLLBACK_REQUIRED: 'ISP 保存失败且中转绑定尚未恢复；请检查中转状态后重新保存配置，暂勿启动连接',
  RELAY_UPSTREAM_INVALID: 'ISP 地址或端口无效',
  RELAY_REVISION_REQUIRED: '请先检查中转状态，再修改 ISP 绑定',
  RELAY_REQUEST_INVALID: '中转请求参数无效',
  DIAGNOSTICS_INVALID: '诊断配置或路径无效，请检查安装位置',
  DIAGNOSTICS_EXPORT_FAILED: '离线诊断包导出失败，请检查本地文件和目录权限',
  STARTUP_RECOVERY_REQUIRED: '启动恢复尚未完成。请保留恢复记录，修复本地文件或处理原受管进程后重新启动；当前禁止保存配置、检测 ISP 和开启会话',
  CORE_NOT_FOUND: '未找到 sing-box 1.14.2，请安装项目固定版本后再保存或连接 ISP',
  ONBOARDING_PATH_INVALID: '配置存储路径异常，请检查运行目录与自定义配置路径',
  ONBOARDING_STATE_INVALID: '首次设置记录无效，请保留原文件后检查',
  ONBOARDING_CONFIG_INVALID: 'ISP 设置无效，请检查地址、端口、协议与账号密码',
  ONBOARDING_CREDENTIALS_INVALID: 'ISP 凭据无效，请重新填写账号与密码',
  ONBOARDING_NEW_CREDENTIALS_REQUIRED: '更改 ISP 地址或原凭据不可读时，需要重新填写完整账号密码，或明确选择无账号验证',
  ONBOARDING_CONFIGURATION_REQUIRED: '请先保存并验证 ISP 配置',
  ONBOARDING_CONFIG_CONFLICT: '配置被其他程序更改，未覆盖新设置，请重新检查',
  ONBOARDING_RECOVERY_REQUIRED: '配置保存恢复未完成，请保留运行目录中的恢复记录后检查',
  ONBOARDING_WRITE_FAILED: 'ISP 设置保存失败，已保留或复原此前配置',
  ONBOARDING_PREFERENCES_INVALID: '会话偏好无效，请重新选择',
  ONBOARDING_VERIFICATION_INVALID: 'ISP 出口核验结果无效，配置未保存',
  ONBOARDING_CONFIG_READONLY: '当前使用外部自定义配置，请在原文件中修改；此界面不会覆盖外部配置或凭据',
  QUALITY_PATH_INVALID: '质量报告存储路径异常，报告未保存',
  QUALITY_PROXY_INVALID: '质量检测代理端口无效，请重新核验 ISP',
  QUALITY_EXIT_UNVERIFIED: '质量检测需要两个独立来源确认同一出口 IP',
  QUALITY_REPORT_INVALID: '质量报告无法读取或格式无效，请重新检测',
  SETUP_PORT_UNAVAILABLE: '无法分配临时检测端口，请稍后重试',
  SETUP_PROXY_UNVERIFIED: '临时检测代理未能确认，检查已停止',
  SETUP_CHECK_FAILED: '两个独立出口检查未同时成功，请检查 ISP 地址、凭据及网络',
  SETUP_VERIFICATION_FAILED: '临时链路验证未完成，请在“诊断与恢复”查看失败步骤和系统错误码',
  SETUP_IP_INVALID: '出口检测未返回有效 IP，配置未保存',
  SETUP_EXIT_MISMATCH: '出口 IP 不一致或不符合指定 IP，检查已停止，原配置保留',
  SETUP_PROXY_STOP_FAILED: '临时检测代理未能安全结束，请检查进程后重试',
  PROXY_STILL_RUNNING: '仍发现代理进程或 TUN 网卡，请先结束后再解除断网锁',
  ADMIN_REQUIRED: 'TUN 需要管理员权限，请以管理员身份运行启动器',
  ADMIN_CHECK_FAILED: '无法检查管理员权限，请以管理员身份运行启动器后重试',
  TUN_STATE_UNAVAILABLE: '无法读取 Windows TUN 网络状态',
  TUN_INTERFACE_IN_USE: '同名 TUN 网卡已被占用，请检查其他代理程序',
  TUN_NOT_READY: 'TUN 网卡、路由或 DNS 尚未就绪，启动已停止',
  DNS_CACHE_CLEAR_FAILED: 'Windows DNS 缓存清理未确认，启动已停止；请保留恢复记录后重试。未能停止的受管核心仍需安全恢复',
  SYSTEM_DNS_FAILED: '本地代理出口已通过，但系统 DNS 解析失败，普通应用尚未确认能走 TUN。请查看诊断日志',
  SYSTEM_NETWORK_TIMEOUT: '本次系统网络出口验证超时，请查看连接状态；已有核验不会因此延长有效期',
  SYSTEM_TLS_FAILED: '本次系统网络出口的 TLS 校验失败，请查看连接状态与诊断',
  SYSTEM_NETWORK_UNREACHABLE: '本次系统默认网络未能访问出口检测站，请查看路由与 DNS 诊断',
  SYSTEM_EXIT_MISMATCH: '系统默认网络出口与代理出口不一致，普通应用可能未走链式连接，连接已停止',
  SYSTEM_RESPONSE_INVALID: '本次系统网络出口检测返回了无效结果，未更新出口核验',
  SYSTEM_HTTP_STATUS: '系统网络出口检测站返回了异常 HTTP 状态，未更新出口核验',
  UPSTREAM_RESOLVE_FAILED: '无法解析 ISP 入口地址',
  PROXY_MODE_INVALID: '代理模式无效',
  MULTI_EXIT_MISMATCH: '多个检测站观察到不一致的出口，代理会话已停止',
  GEO_UNVERIFIED: '无法可靠确定当前 ISP 出口国家、城市和时区，系统设置保持原样',
  EXIT_GEO_UNVERIFIED: '出口位置证据不足，环境设置保持原样',
  TIMEZONE_UNSUPPORTED: '出口时区尚无可靠的 Windows 映射，该项保持原样；其他项目按逐项结果确认',
  ENVIRONMENT_PATH_INVALID: '环境备份路径异常，请检查运行目录',
  ENVIRONMENT_PROFILE_INVALID: '环境方案无效，请完整检查国家或地区、时区、首选语言和区域格式；已保存方案保留',
  ENVIRONMENT_PROFILE_FOREIGN: '环境方案属于其他电脑或 Windows 用户，未覆盖当前设置；请使用本机方案',
  ENVIRONMENT_PROFILE_CONFLICT: '环境方案已被其他窗口修改，未覆盖新方案；请重新读取后再保存',
  ENVIRONMENT_DAILY_REQUIRED: '请先在“系统环境”设置并保存日常环境，再恢复；原始快照复原位于高级恢复中',
  ENVIRONMENT_STATE_INVALID: '环境恢复记录无效。请在第二步点击“刷新本机快照”；旧记录会先归档保留',
  ENVIRONMENT_SNAPSHOT_INVALID: '读取到的本机时区、语言或输入法信息无效，尚未保存新快照；请检查本机环境读取结果后重试',
  ENVIRONMENT_BACKUP_UNBOUND: '旧快照尚未绑定此电脑，请先刷新本机快照；未应用旧设置',
  ENVIRONMENT_BACKUP_FOREIGN: '快照来自其他电脑或用户，请先刷新本机快照；未应用旧设置',
  ENVIRONMENT_IDENTITY_UNAVAILABLE: '无法确认此电脑和当前用户身份，未建立或应用快照，请检查本机权限',
  ENVIRONMENT_BACKUP_SESSION_ACTIVE: '请先结束代理和独立浏览器会话，再刷新本机快照',
  ENVIRONMENT_REBUILD_REQUIRED: '请在第二步明确刷新本机快照；旧恢复记录会先归档保留',
  ENVIRONMENT_WINDOWS_FAILED: 'Windows 环境操作失败，请检查权限和语言支持；恢复快照已保留',
  ENVIRONMENT_PERMISSION_DENIED: 'Windows 拒绝了环境设置权限，请检查当前用户权限；恢复快照已保留',
  ENVIRONMENT_TIMEOUT: 'Windows 环境操作超时，请检查当前状态；恢复快照已保留',
  ENVIRONMENT_VERIFY_FAILED: '部分环境设置尚未匹配，请查看逐项结果；已生效设置与原始恢复记录保留',
  ENVIRONMENT_PARTIAL: '部分环境设置尚未匹配，已成功的设置保留；请查看逐项结果并重新应用',
  ENVIRONMENT_RESTORE_REQUIRED: '环境操作未完整完成；可手动重新应用出口环境，或还原初始环境；原始备份已保留',
  ENVIRONMENT_CONFLICT: '环境设置或恢复记录已发生变化。可手动重新应用出口环境，或还原初始环境；恢复记录冲突时请退出其他 MC Proxy 实例后重试',
  ENVIRONMENT_BACKUP_DRIFT: '当前环境与原始快照不同。可手动重新应用出口环境，或还原初始环境；原始备份保留，代理连接可继续',
  ENVIRONMENT_BACKUP_ACTIVE: '仍有旧环境恢复记录。可一键复原，或明确选择“以当前环境为准”归档旧记录并建立新快照',
  ENVIRONMENT_OPTIMIZATION_FAILED: '环境优化未完成，请检查备份和本机权限',
  CLAUDE_PATH_UNSAFE: 'Claude 目录含链接或非预期路径，未继续清理',
  CLAUDE_RUNNING: 'Claude Code 或相关进程仍在运行，请退出后重新预览',
  CLAUDE_PROCESS_UNREADABLE: '无法确认 Claude 进程已退出，清理已拒绝',
  CLAUDE_PROJECT_PRESENT: 'Claude 数据目录包含 worktrees 项目，请先迁移项目后再清理',
  CLAUDE_INVENTORY_CHANGED: '文件清单已变化，请重新预览并确认清理',
  CLAUDE_CLEANUP_FAILED: 'Claude 数据未完整清理，请重新预览检查残留',
  CLAUDE_INSPECT_FAILED: '无法安全检查 Claude 目录或进程，请检查权限',
  NETWORK_LOCK_BACKUP_INVALID: '防火墙备份校验失败，拒绝覆盖当前策略，请保留恢复目录',
  NETWORK_LOCK_CONFLICT: '防火墙策略发生外部变更，拒绝覆盖；请核对断网锁恢复记录',
  NETWORK_LOCK_ENDPOINT_CHANGED: 'ISP 入口或 core 已改变，请先安全结束并明确解锁后再切换',
  NETWORK_LOCK_INPUT_INVALID: '断网锁需要固定的 ISP 地址、端口及受管 core',
  NETWORK_LOCK_TUN_REQUIRED: '请先建立并验证 TUN 连接，再手动开启断网锁',
  NETWORK_LOCK_IMPORTED_UNAVAILABLE: '导入线路的全局 TUN 暂不支持断网锁，请使用正常断开连接恢复网络',
  GLOBAL_VPN_CONFLICT: '检测到其他活动 VPN 的 TUN/TAP，请先关闭该 VPN 再使用 MC Proxy 全局模式；软件不会自动关闭外部 VPN',
  GLOBAL_VPN_CHECK_FAILED: '无法确认其他 VPN 的 TUN 状态，全局模式尚未启动，请重试或使用应用分流',
  VPN_INTERFACE_STATE_UNAVAILABLE: '无法确认其他 VPN 的网卡状态，全局模式尚未启动，请重试或使用应用分流',
  PROXY_MODE_INVALID: '接管方式必须是应用分流或全局 TUN',
  PROXY_NOT_RUNNING: '受管代理未运行，请先启动 ISP 连接',
  NETWORK_LOCK_INSPECTION_FAILED: '无法完整读取 Windows 防火墙策略，断网锁未确认',
  NETWORK_LOCK_PATH_INVALID: '断网锁恢复目录异常，拒绝更改防火墙',
  NETWORK_LOCK_POLICY_UNSUPPORTED: '当前防火墙服务、组策略或接口例外不支持可靠锁定，断网锁未开启',
  NETWORK_LOCK_RECOVERY_REQUIRED: '断网锁操作未完成，保留现有阻断；请检查并明确恢复网络',
  NETWORK_LOCK_RESTORE_FAILED: '防火墙原始策略恢复未完成，请保留恢复记录并重试',
  NETWORK_LOCK_STATE_INVALID: '断网锁恢复记录无效，请保留记录后检查',
  NETWORK_LOCK_LEGACY_RECOVERY_REQUIRED: '检测到旧版防火墙断网锁，请先安全结束连接并完成网络修复，再启用新版独立断网锁',
  NETWORK_LOCK_HELPER_UNAVAILABLE: '未找到断网保护组件，断网锁未确认；请保留恢复记录',
  NETWORK_LOCK_WFP_FAILED: 'Windows 独立过滤策略操作未确认，恢复记录已保留；请查看错误码后重试或使用网络修复',
  NETWORK_LOCK_SERVICE_UNAVAILABLE: '断网保护服务未就绪，持久保护尚未确认',
  NETWORK_LOCK_SERVICE_CONFLICT: '断网保护服务路径或权限发生变化，请保留记录后检查，软件未覆盖现有服务',
  NETWORK_LOCK_TUN_UNAVAILABLE: '未确认 MC Proxy 专属 TUN 网卡，断网锁未改变',
  NETWORK_LOCK_ORPHANED: '发现 MC Proxy 独立保护规则，但本机缺少对应记录，请先使用网络修复',
  NETWORK_LOCK_RECHECK_REQUIRED: '断网保护状态需要重新核验，代理线路保持运行，请查看保护面板',
  NETWORK_LOCK_DISABLED: '断网锁开发已暂停，当前连接不受影响。旧锁记录仍可通过网络修复恢复。',
  NETWORK_LOCK_VERIFY_FAILED: '无法验证断网锁已完整生效；保留现有规则，请检查并恢复网络',
  NETWORK_LOCK_WINDOWS_FAILED: 'Windows 防火墙操作失败，恢复记录已保留。请使用网络修复并查看报告',
  NETWORK_LOCK_TIMEOUT: 'Windows 防火墙操作超时，恢复记录已保留。请使用网络修复并查看报告',
  NETWORK_LOCK_RESPONSE_INVALID: 'Windows 防火墙检查结果无法读取，恢复记录已保留',
  NETWORK_LOCK_EXPORT_FAILED: '原始防火墙备份导出失败，启动已停止',
  NETWORK_LOCK_IMPORT_FAILED: 'Windows 未能导入原始防火墙备份，请使用网络修复并查看报告',
  CONFIG_READ_FAILED: '无法读取配置，请检查 runtime/config.json 和当前用户权限',
  CONFIG_INVALID: '代理配置无效，请检查本地配置',
  SECRETS_READ_FAILED: '无法读取 ISP 凭据文件，请检查当前用户权限',
  SECRETS_INVALID: 'ISP 凭据配置无效',
  ACL_FAILED: '无法保护运行目录权限，启动已停止',
  OUTPUT_UNAVAILABLE: '无法创建私有运行目录，请检查数据目录是否可写、磁盘空间及文件占用',
  EXPECTED_EXIT_REQUIRED: '请先在配置中固定 expectedExitIps，再启动会话',
  EXIT_IP_MISMATCH: '出口 IP 与配置不匹配，会话已阻止',
  EXIT_UNVERIFIED: '出口尚未通过指定 IP 校验',
  APPLICATION_TARGET_INVALID: '应用检测只支持 Claude 或 Codex 的固定目标，以及代理或系统路径',
  APPLICATION_SYSTEM_UNVERIFIED: '系统路径检测需要当前已核验的受管全局 TUN，请先连接并确认系统出口',
  PROXY_OFFLINE: '受管代理未运行，请先启动 ISP 连接',
  PROXY_STOPPED: '会话已停止，请先启动 ISP 连接',
  PROXY_CONFIG_CHANGED: '配置已改变，请安全结束会话后重新启动',
  SESSION_CHANGED: '会话已改变，旧操作已取消，请重新操作',
  PROXY_PORT_OCCUPIED: '代理端口已被其他进程占用，未接管或停止该进程',
  PROXY_PORT_IN_USE: '代理端口已被其他进程占用，未接管或停止该进程',
  PROXY_ALREADY_MANAGED: '受管代理仍在运行，请先安全结束会话再切换配置',
  PROXY_CONTROLLER_ACTIVE: '另一个 MC Proxy 控制进程仍在使用此运行目录，请先关闭原窗口或旧版控制服务后重试；未接管或停止其代理',
  PROXY_STATE_INVALID: '代理恢复记录无效，请保留运行目录后检查',
  CORE_CHECK_FAILED: '无法运行或校验 sing-box，请检查固定版本及配置',
  CORE_VERSION_INVALID: '请使用项目固定的 sing-box 1.14.2',
  CORE_START_FAILED: 'sing-box 未能建立受管代理监听',
  CORE_OWNERSHIP_UNVERIFIED: 'core 可能仍在运行，但身份无法确认；请检查进程，未强制停止',
  PROXY_EXITED: '受管代理进程已意外退出',
  PROCESS_STOP_TIMEOUT: '受管进程尚未退出，请检查状态后重试',
  RUNTIME_UNSAFE: '运行目录路径异常，操作已拒绝',
  PROXY_CONNECT_REJECTED: '本地代理未建立目标隧道；请查看 CONNECT 状态和核心错误，不能仅凭此判断 ISP 或网站故障',
  PROXY_UNREACHABLE: '本地代理无法连接',
  PROXY_TIMEOUT: '代理连接超时',
  PROXY_CLOSED: '代理连接已中断',
  PROBE_TIMEOUT: '出口验证超时，未确认本次连接',
  PROBE_TLS_OR_SOCKET_FAILED: '出口验证的 TLS 或网络连接失败',
  PROBE_HTTP_STATUS: '出口探测端点返回异常状态',
  PROBE_REQUEST_FAILED: '出口探测请求失败',
  PROBE_RESPONSE_FAILED: '出口探测响应读取失败',
  PROBE_RESPONSE_TOO_LARGE: '出口探测响应超出大小限制',
  PROXY_RESPONSE_INVALID: '本地代理隧道响应无效',
  PROBE_IP_INVALID: '出口探测未返回有效 IP',
  PROXY_PORT_INVALID: '端口必须来自本地配置，不能由网页任意切换',
  CONFIRMATION_REQUIRED: '请先预览并明确确认此操作',
  CONFIRMATION_INVALID: '计划已过期、已使用或已失效，请重新预览',
  BROWSER_ALREADY_RUNNING: '独立浏览器已经运行，请先安全结束会话',
  BROWSER_CLOSE_TIMEOUT: '浏览器尚未正常退出，请处理窗口提示后重试；代理暂时保留',
  BROWSER_SESSION_UNTRACKED: '此会话没有可验证的启动身份；请在该浏览器内退出一次，再从 MC Proxy 重新打开。其他浏览器不会被关闭',
  BROWSER_LAUNCH_FAILED: '浏览器启动失败，请检查安装或运行权限',
  BROWSER_IDENTITY_UNVERIFIED: '浏览器进程身份尚未确认，请关闭独立窗口后重试',
  BROWSER_UNAVAILABLE: '未找到所选浏览器，请在会话准备中选择本机已安装的 Chrome 或 Edge 后重试',
  BROWSER_EXECUTABLE_INVALID: '浏览器安装路径无效或不可安全访问，请选择本机 chrome.exe 或 msedge.exe',
  VPN_CONFIRMATION_REQUIRED: '请先开启外部 VPN，再勾选确认并检测 ISP 连接',
  VPN_PROXY_INVALID: 'VPN 本地代理只支持本机 HTTP 或 SOCKS5 端口，不能使用项目自己的代理端口',
  VPN_COMPAT_HTTP_ONLY: 'VPN 兼容模式只提供本地 HTTP 代理，不启动第二套 TUN 或断网锁',
  VPN_COMPAT_NO_ROUTE: '未找到通过 ISP 出口核验的网络路径。请检查 VPN；若它只提供本地代理，请填写其 HTTP 或 SOCKS5 端口后重试',
  VPN_IMPORT_INVALID: '导入配置记录无效，请重新导入受支持的配置文件或节点链接',
  VPN_IMPORT_READ_FAILED: '无法读取本机导入配置，请检查私有目录权限',
  VPN_IMPORT_WRITE_FAILED: '导入配置未能安全保存，原配置保留',
  VPN_IMPORT_CONFLICT: '导入配置已被其他操作更改，请刷新后重试',
  VPN_IMPORT_NO_SUPPORTED_NODES: '配置中没有可转换的节点，原配置保留。请查看不支持的节点原因与协议范围',
  VPN_IMPORT_NO_ROUTE: '已尝试的配置节点均未通过 ISP 出口核验，请查看节点结果或指定其他节点',
  VPN_NODE_NOT_FOUND: '所选节点不在当前配置中，请重新选择',
  VPN_NODE_REQUIRED: '请先导入包含受支持节点的配置文件或节点链接',
  VPN_NODE_INVALID: 'VPN 节点配置无效，未建立链路',
  VPN_NODE_RESOLVE_FAILED: '无法解析配置节点地址，请检查当前网络或选择其他节点',
  VPN_YAML_SIZE_INVALID: '配置内容大小不能超过 1 MiB',
  VPN_YAML_INVALID: 'YAML 文件格式无效，原导入配置保留',
  VPN_YAML_PROXIES_INVALID: '文件没有有效的 proxies 节点列表',
  VPN_YAML_NODE_LIMIT: '配置节点数量不能超过 256 个',
  VPN_CONFIG_FORMAT_UNSUPPORTED: '未识别到受支持的本地配置或节点链接，原配置保留。请使用 Clash/Mihomo、sing-box、V2Ray/Xray、分享链接、Base64 节点文本或受支持的 INI 配置',
  BROWSER_PATH_UNSAFE: '独立浏览器目录包含非预期链接或路径，操作已拒绝',
  BROWSER_STATE_INVALID: '独立浏览器恢复记录无效，请保留文件后检查',
  PROCESS_IDENTITY_MISMATCH: '进程身份已经改变，未停止其他程序',
  PROCESS_QUERY_FAILED: '无法核验 Windows 进程，请检查当前用户权限',
  APPLICATION_LEASE_INVALID: '应用代理授权已失效，请先完成当前出口核验；未切换为直连',
  APPLICATION_PROXY_TIMEOUT: '应用代理等待本机授权或目标连接超时，请查看诊断；未切换为直连',
  APPLICATION_PROXY_OVERLOADED: '应用代理并发请求过多，请稍后重试',
  APPLICATION_PROXY_RECURSION: '应用代理检测到递归连接，请求已拒绝',
  APPLICATION_PRIVATE_DNS_FAILED: '本机或内网名称未能解析为可信内网地址，请检查本地服务',
  APPLICATION_REQUEST_ABORTED: '应用请求已取消',
  APPLICATION_CONNECT_FAILED: '应用代理连接失败，请查看本机授权与目标连接诊断；未切换为直连',
  APPLICATION_RESPONSE_TIMEOUT: '应用代理等待目标响应超时',
  PLATFORM_UNSUPPORTED: '受管浏览器第一版需要 Windows',
  OPERATION_FAILED: '操作失败，请检查本地配置、程序安装和权限',
};

export const CONTROL_ERROR_CODES = Object.freeze(Object.keys(ERROR_MESSAGES));
const failureCode = cause => Object.hasOwn(ERROR_MESSAGES, cause?.code) ? cause.code
  : sanitizeSetupDiagnostic(cause?.diagnostic)?.setupStage ? 'SETUP_VERIFICATION_FAILED' : 'OPERATION_FAILED';

export function createControllerState({ proxyPort = 17890 } = {}) {
  return {
    proxy: { port: proxyPort, requestedStop: true, running: false, managed: false, exit: null },
    plans: new Map(), revision: 0, initialized: false, phase: 'idle', lastError: null, operation: null,
    configuration: { available: false }, configHash: null, sessionConfigHash: null,
    browser: { running: false, browser: null, language: null },
  };
}

export function createControllerServer(options = {}) {
  const controlToken = randomBytes(32).toString('hex');
  const mock = options.mock ?? (process.env.PROXYPILOT_MOCK === '1');
  const state = options.state || createControllerState(options);
  const runtimeRoot = path.resolve(options.runtimeRoot || path.join(backendRoot, 'runtime'));
  const now = options.now || Date.now;
  const fingerprintRoot = options.fingerprintRoot ? path.resolve(options.fingerprintRoot) : path.join(runtimeRoot, FINGERPRINT_BROWSER_INSTALL_DIRECTORY);
  let browserObservation = null;
  let fingerprintInstall = { status: 'idle' }, fingerprintInstallWork = null, fingerprintInstallAbort = null;
  const probeExit = options.probe || probe;
  const probeSystem = options.probeSystemExit || probeSystemExit;
  const request = options.requestViaProxy || requestViaProxy;
  const systemRequest = options.directHttpsRequest || directHttpsRequest;
  // The distribution supplies the trust anchor. Renderer/API input cannot
  // change the licensing mode, service origin or signing keys.
  const licensing = options.licenseClient || createLicenseClient({
    stateDir: path.join(runtimeRoot, '.license'), config: options.licenseConfig,
    now, getProxy: () => {
      if (!state.proxy.running) return null;
      const verified = state.proxy.managed && !state.proxy.requestedStop && !closing && !repairPending && !blockPending
        && networkLifecycle.state === 'stable' && freshObservation(state.proxy.exit, state.configHash)
        && (state.proxy.mode !== 'tun' || freshObservation(state.proxy.systemExit, state.configHash));
      return verified ? { proxyPort: state.proxy.port, verified: true } : { unavailable: true };
    },
  });
  let gatewayIdentityRead = null;
  const applicationGateway = options.applicationGateway || createApplicationProxy({
    // Match the 15s Windows owned-state deadline. Remote sockets retain their
    // separate 8s budget; successful native identities are not cached.
    authorizationTimeoutMs: 16_000,
    authorize: async binding => {
      const permitted = () => Boolean(licensing.status().allowed && !closing && !repairPending && !blockPending && networkLifecycle.state === 'stable' && state.proxy.running && state.proxy.managed && !state.proxy.requestedStop
        && state.revision === binding.revision && state.proxy.port === binding.upstreamPort && freshObservation(state.proxy.exit, state.configHash)
        && (state.proxy.mode !== 'tun' || freshObservation(state.proxy.systemExit, state.configHash)));
      if (!permitted()) return false;
      const key = exitBinding(state.configHash);
      let current = gatewayIdentityRead;
      if (!current || current.key !== key) {
        current = { key, promise: runtime.inspectOwnedState ? runtime.inspectOwnedState() : runtime.status() }; gatewayIdentityRead = current;
        const reading = current;
        void current.promise.finally(() => { if (gatewayIdentityRead === reading) gatewayIdentityRead = null; }).catch(() => {});
      }
      const live = await current.promise;
      return live.inspectionSuperseded !== true && permitted() && exitBinding(state.configHash) === key && live.running && live.managed && live.port === binding.upstreamPort && live.mode === state.proxy.mode
        && (live.sessionId || null) === (state.proxy.sessionId || null) && (live.vpnNodeHash || null) === (state.proxy.vpnNodeHash || null)
        && (live.mode !== 'tun' || live.tunReady === true);
    },
    onFailure: event => diagnostic({ ...event, operation: 'application-connect' }),
  });
  let queue = Promise.resolve();
  let healthBusy = false;
  let exitVerification = null;
  let healthState = { state: 'idle', checkedAt: null, errorCode: null };
  let closing = false;
  let shutdownWork = null;
  let repairPending = false;
  let blockPending = false;
  let lastHealthCheck = 0;
  let startupRecoveryError = null;
  let queuedOperations = 0; let statusRefresh = null; let statusCheckedAt = null;
  let networkLifecycle = { state: 'stable', reason: null };
  let networkGeneration = 0; let networkRefresh = null;
  let connectionAttempt = null;
  let deliveryAbort = null;
  let sessionAbort = new AbortController();
  let licenseSuspended = null;
  const serialized = work => {
    queuedOperations++;
    const result = queue.then(work, work).finally(() => { queuedOperations--; });
    queue = result.catch(() => {}); return result;
  };
  function diagnostic(event) {
    const details = sanitizeNetworkLockDiagnostic(event.diagnostic) || {};
    if (Number.isSafeInteger(event.diagnostic?.exitCode)) details.exitCode = event.diagnostic.exitCode;
    if (Number.isInteger(event.diagnostic?.httpStatus) && event.diagnostic.httpStatus >= 100 && event.diagnostic.httpStatus <= 599) details.httpStatus = event.diagnostic.httpStatus;
    Object.assign(details, probeDiagnostic(event));
    if (['SIGTERM', 'SIGKILL', 'SIGINT', 'SIGABRT', 'SIGSEGV', 'SIGBREAK'].includes(event.diagnostic?.signal)) details.signal = event.diagnostic.signal;
    const environmentDiagnostic = sanitizeEnvironmentDiagnostic(event.diagnostic);
    if (environmentDiagnostic) Object.assign(details, environmentDiagnostic);
    try { options.onDiagnostic?.({ code: /^[A-Z_]{1,80}$/.test(event.code || '') ? event.code : 'OPERATION_FAILED', operation: /^[a-z-]{1,80}$/.test(event.operation || '') ? event.operation : state.phase, ...(Object.keys(details).length ? { diagnostic: details } : {}) }); } catch {}
  }

  function invalidate() {
    state.revision++; state.proxy.exit = null; state.proxy.systemExit = null; state.plans.clear(); gatewayIdentityRead = null;
    browserObservation?.invalidate();
    runtime.invalidateOwnedState?.();
    void Promise.resolve(applicationGateway.pause ? applicationGateway.pause() : applicationGateway.stop()).catch(() => {});
  }
  function cancelSessionWork(cause = error('CONNECTION_CANCELED', ERROR_MESSAGES.CONNECTION_CANCELED)) {
    connectionAttempt?.controller.abort(cause); deliveryAbort?.abort(cause); sessionAbort.abort(cause);
  }
  function checkCanceled(signal) { if (signal?.aborted) throw signal.reason?.code ? signal.reason : error('CONNECTION_CANCELED', ERROR_MESSAGES.CONNECTION_CANCELED); }
  function cancelableRead(promise, signal = sessionAbort.signal) {
    if (signal?.aborted) void Promise.resolve(promise).catch(() => {});
    checkCanceled(signal);
    return new Promise((resolve, reject) => {
      const abort = () => { signal.removeEventListener('abort', abort); reject(signal.reason?.code ? signal.reason : error('CONNECTION_CANCELED', ERROR_MESSAGES.CONNECTION_CANCELED)); };
      signal.addEventListener('abort', abort, { once: true });
      Promise.resolve(promise).then(value => { signal.removeEventListener('abort', abort); resolve(value); }, cause => { signal.removeEventListener('abort', abort); reject(cause); });
      if (signal.aborted) abort();
    });
  }
  async function resumeApplicationGateway() {
    if (!applicationGateway.status().running || !licensing.status().allowed || state.proxy.requestedStop || networkLifecycle.state !== 'stable') return;
    if (!freshObservation(state.proxy.exit, state.configHash) || state.proxy.mode === 'tun' && !freshObservation(state.proxy.systemExit, state.configHash)) return;
    await applicationGateway.start({ upstreamPort: state.proxy.port, revision: state.revision });
  }
  const exitBinding = fingerprint => JSON.stringify([state.revision, fingerprint, state.proxy.port, state.proxy.mode, state.proxy.sessionId || null, state.proxy.vpnNodeHash || null]);
  const freshObservation = (observation, fingerprint) => Boolean(observation && now() >= observation.checkedAt && now() - observation.checkedAt <= EXIT_TTL
    && observation.revision === state.revision && observation.configHash === fingerprint && observation.binding === exitBinding(fingerprint));
  function invalidateBrowserPlans() { for (const [token, plan] of state.plans) if (plan.type === 'browser') state.plans.delete(token); }
  function probeDiagnostic(cause) {
    const details = { ...sanitizeProbeFailure(cause)?.diagnostic, ...sanitizeSetupDiagnostic(cause?.diagnostic) };
    if (cause?.diagnostic?.operation === 'owned-state' && ['timeout', 'query-failed'].includes(cause.diagnostic.category)) {
      details.operation = 'owned-state'; details.category = cause.diagnostic.category;
      if (Number.isSafeInteger(cause.diagnostic.elapsedMs) && cause.diagnostic.elapsedMs >= 0 && cause.diagnostic.elapsedMs <= 120_000) details.elapsedMs = cause.diagnostic.elapsedMs;
    }
    if (cause?.code === 'SETUP_CHECK_FAILED' && Array.isArray(cause.diagnostic?.checks)) {
      const checks = cause.diagnostic.checks.slice(0, 2).flatMap(check => {
        const safe = sanitizeProbeFailure({ code: check?.code, diagnostic: check });
        return safe && ['ipify', 'cloudflare'].includes(check.source) ? [{ source: check.source, code: safe.code, ...safe.diagnostic }] : [];
      });
      if (checks.length) details.checks = checks;
    }
    return details;
  }
  function rememberFailure(cause) {
    const stage = state.operation?.stage || state.phase;
    const details = sanitizeNetworkLockDiagnostic(cause?.diagnostic);
    const environmentDetails = sanitizeEnvironmentDiagnostic(cause?.diagnostic);
    const probeDetails = probeDiagnostic(cause);
    const code = failureCode(cause);
    state.lastError = { code, message: ERROR_MESSAGES[code], at: timestamp(),
      ...(/^[a-z-]{1,80}$/.test(stage || '') ? { stage } : {}),
      ...(details || environmentDetails || Object.keys(probeDetails).length ? { diagnostic: { ...details, ...environmentDetails, ...probeDetails } } : {}) };
    state.phase = 'error';
  }
  function assertStartupRecovered() {
    if (startupRecoveryError) throw error('STARTUP_RECOVERY_REQUIRED', ERROR_MESSAGES.STARTUP_RECOVERY_REQUIRED);
  }
  const startupRecovery = () => ({ required: Boolean(startupRecoveryError), ...(startupRecoveryError ? { error: { ...startupRecoveryError } } : {}) });
  const runtime = options.runtime || createProxyRuntime({
    runtimeRoot, configPath: options.configPath, secretsPath: options.secretsPath, corePath: options.corePath, mock,
    onFailure: cause => { invalidate(); state.proxy.running = false; rememberFailure(cause); },
    onProgress: operation => { state.operation = { stage: String(operation.stage || '').slice(0, 80), message: String(operation.message || '').slice(0, 250), at: timestamp() }; diagnostic({ code: 'CONNECTION_PROGRESS', operation: operation.stage }); },
    onDiagnostic: diagnostic,
  });
  const browsers = options.browsers || createBrowserManager({ runtimeRoot, mock, fingerprintRoot });
  const fingerprintSecurity = options.fingerprintSecurity || createFingerprintSecurityCheck({ version: FINGERPRINT_BROWSER_RELEASE.version, now, mock });
  const workspaces = options.workspaces || createBrowserWorkspaceManager({ runtimeRoot, mock, now });
  let browserOptions = [];
  const environment = options.environment || createEnvironmentManager({ stateDir: path.join(runtimeRoot, '.environment'), mock });
  const claudeCleanup = options.claudeCleanup || createClaudeCleanupManager({ homeDir: os.homedir(), localAppDataDir: process.env.LOCALAPPDATA, roamingAppDataDir: process.env.APPDATA, mock });
  const onboarding = options.onboarding || createOnboardingManager({ runtimeRoot, configPath: options.configPath, secretsPath: options.secretsPath, mock });
  browserObservation = options.browserObservation || createBrowserObservation({ mock, assetsRoot: frontendRoot, now, dnsProbe: options.dnsProbe,
    getContext: () => ({ mode: state.proxy.mode }),
    isCurrent: (binding, target) => !closing && !repairPending && !blockPending && licensing.status().allowed && state.proxy.running && state.proxy.managed && !state.proxy.requestedStop
      && networkLifecycle.state === 'stable' && binding.revision === state.revision && binding.configHash === state.configHash
      && binding.exitBinding === hash(exitBinding(state.configHash)) && freshObservation(state.proxy.exit, state.configHash)
      && (!target?.managedLaunchVerified || state.browser?.running && state.browser?.managed
        && (state.browser.workspaceId || null) === (target.workspaceId || null) && observationTarget(state.browser).identityRevision === target.identityRevision),
  });
  const setupVerifier = options.setupVerifier || createSetupVerifier({ runtimeRoot, corePath: options.corePath, mock,
    onProgress: operation => { state.operation = { ...operation, at: timestamp() }; },
    onDiagnostic: diagnostic,
  });
  const qualityReports = options.qualityReports || createQualityReportStore({ runtimeRoot, mock, request, now });
  const relayManager = options.relayManager || createRelayManager({ runtimeRoot, mock });
  const vpnConfigStore = options.vpnConfigStore || createImportedVpnStore({ stateDir: path.join(runtimeRoot, '.vpn-config'), mock });
  const screenImportedNodes = createImportedNodeScreening({ now });
  const subscriptions = options.subscriptions || createVpnSubscriptionManager({ store: vpnConfigStore, getProxyLease: applicationProxyLease, now });
  const serviceReminders = options.serviceReminders || createServiceReminderManager({ runtimeRoot, mock, now });
  let deliveryRevision = null;
  const deliveryImporter = options.deliveryImporter || createCustomerDeliveryImporter({ runtimeRoot, configPath: options.configPath, secretsPath: options.secretsPath,
    licenseClient: licensing, licenseConfig: options.licenseConfig, onboarding, setupVerifier, vpnConfigStore, now, mock,
    assertIdle: () => assertSetupIdle(), assertCurrent: () => assertSetupRevision(deliveryRevision),
    onProgress: operation => { state.operation = { ...operation, at: timestamp() }; },
  });
  const requireRelay = options.requireRelay === true;
  let relayState = { configured: false, required: requireRelay, mock };
  let compatibilityState = null;
  let vpnLatencyState = null;
  let vpnLatencyCache = null;
  let vpnConfigState = { available: false, id: null, selectedIndex: null, total: 0, supported: 0, unsupported: 0, nodes: [], unsupportedNodes: [], mock };
  let environmentState = { status: 'not_checked' };
  let latestReport = null;
  let reportRevision = null;
  let browserGeography = null;
  let networkLockState = { state: 'unavailable', status: 'unavailable', locked: false, persistent: false, canUnlock: false };
  async function refreshNetworkLock({ force = false, cached = false } = {}) {
    if (runtime.networkLock) {
      const lock = cached && runtime.networkLock.snapshot ? runtime.networkLock.snapshot() : await runtime.networkLock.status({ force });
      networkLockState = { ...lock, status: lock.status || lock.state };
    }
    return networkLockState;
  }
  function networkLockVerified(){
    return networkLockState.locked&&!networkLockState.inspectionFailed;
  }

  async function refreshVpnConfig() {
    try { vpnConfigState = await vpnConfigStore.status(); }
    catch (cause) { vpnConfigState = { available: false, nodes: [], supported: 0, unsupported: 0, errorCode: Object.hasOwn(ERROR_MESSAGES, cause.code) ? cause.code : 'VPN_IMPORT_READ_FAILED', mock }; }
    if (vpnLatencyState && vpnLatencyState.profileId !== vpnConfigState.id) { vpnLatencyState = null; vpnLatencyCache = null; }
    if (vpnLatencyCache && (vpnConfigState.selectedIndex !== vpnLatencyCache.selectedIndex
      || hash((await vpnConfigStore.candidates()).map(node => ({ index: node.index, hash: hash(node.outbound) }))) !== vpnLatencyCache.nodeKey)) {
      vpnLatencyState = null; vpnLatencyCache = null;
    }
    return vpnConfigState;
  }

  const publicVpnLatency = () => vpnLatencyState ? { ...vpnLatencyState, stale: !vpnLatencyCache || now() - vpnLatencyCache.createdAt >= VPN_LATENCY_TTL } : null;

  async function assertImportedConfiguration(config) {
    if (config.connectionMode !== 'vpn-import') return;
    const candidates = await vpnConfigStore.candidates();
    if (!candidates.length) throw error('VPN_NODE_REQUIRED', ERROR_MESSAGES.VPN_NODE_REQUIRED);
    if (state.proxy.running && (!state.proxy.vpnNodeHash || !candidates.some(node => hash(node.outbound) === state.proxy.vpnNodeHash))) throw error('VPN_IMPORT_CONFLICT', ERROR_MESSAGES.VPN_IMPORT_CONFLICT);
  }

  async function checkEnvironment(body = {}) {
    if (Object.keys(body).some(key => !['refreshBackup', 'rebuildBackup', 'confirm'].includes(key))) throw error('INPUT_INVALID', '环境检查包含未知选项', 400);
    if (body.refreshBackup !== undefined && typeof body.refreshBackup !== 'boolean') throw error('INPUT_INVALID', '重新备份选项必须为布尔值', 400);
    if (body.rebuildBackup !== undefined && typeof body.rebuildBackup !== 'boolean') throw error('INPUT_INVALID', '重建快照选项必须为布尔值', 400);
    if (body.rebuildBackup === true) {
      if (body.refreshBackup !== true) throw error('INPUT_INVALID', '重建快照需要明确刷新当前环境', 400);
      confirmed(body); assertStartupRecovered();
      const [live, browser] = await Promise.all([runtime.status(), browsers.status()]);
      if (live.running || browser.running) throw error('ENVIRONMENT_BACKUP_SESSION_ACTIVE', ERROR_MESSAGES.ENVIRONMENT_BACKUP_SESSION_ACTIVE);
    }
    state.operation = { stage: 'checking-environment', message: '正在检查时区、语言、输入法并保存环境快照', at: timestamp() };
    try { environmentState = await environment.check({ refreshBackup: body.refreshBackup === true, rebuildBackup: body.rebuildBackup === true }); return environmentState; }
    finally { environmentState = environment.status(); state.operation = null; }
  }

  async function adoptCurrentEnvironment(body = {}) {
    if (Object.keys(body).some(key => key !== 'confirm')) throw error('INPUT_INVALID', '采纳当前环境包含未知选项', 400);
    confirmed(body); assertStartupRecovered();
    const [live, browser] = await Promise.all([runtime.status(), browsers.status()]);
    if (live.running || browser.running) throw error('ENVIRONMENT_BACKUP_SESSION_ACTIVE', ERROR_MESSAGES.ENVIRONMENT_BACKUP_SESSION_ACTIVE);
    state.operation = { stage: 'adopting-current-environment', message: '正在读取当前 Windows 环境并归档旧恢复记录…', at: timestamp() };
    try { environmentState = await environment.adoptCurrent(); return environmentState; }
    finally { environmentState = environment.status(); state.operation = null; }
  }

  async function recordEnvironmentFailure(cause, stage) {
    diagnostic({ code: cause.code || 'ENVIRONMENT_OPTIMIZATION_FAILED', operation: 'environment-optimization', diagnostic: cause.diagnostic });
    const current = environment.status();
    if (!stage && ['failed', 'recovery-required'].includes(current.optimization?.status) && (current.optimization.code === cause?.code || current.optimization.code === 'ENVIRONMENT_OPTIMIZATION_FAILED')) {
      environmentState = current;
      return;
    }
    try {
      if (environment.noteOptimizationFailure) {
        environmentState = await environment.noteOptimizationFailure(cause, stage || 'preflight');
        return;
      }
    } catch { /* A failed journal must not hide the optimization failure. */ }
    const code = ERROR_MESSAGES[cause?.code] ? cause.code : 'ENVIRONMENT_OPTIMIZATION_FAILED';
    const message = ERROR_MESSAGES[code];
    environmentState = { ...current, optimization: { status: current.status === 'recovery-required' ? 'recovery-required' : 'failed', code, message, stage: stage || 'preflight', completedAt: timestamp(), persisted: false }, warnings: [...new Set([...(current.warnings || []), message])] };
  }

  async function onboardingStatus() {
    if (startupRecoveryError) { await refreshRelay(); return {
      onboarding: { firstRun: true, completedAt: null, preferences: {}, mock, recoveryRequired: true, backupExists: Boolean(environmentState.backup) },
      configuration: { available: false, pinned: false, expectedExitIps: [], credentialsConfigured: false, errorCode: 'STARTUP_RECOVERY_REQUIRED' },
      environment: environmentState, startupRecovery: startupRecovery(), relay: relayState, vpnConfig: await refreshVpnConfig(), vpnLatency: publicVpnLatency(),
    }; }
    const preferences = await onboarding.status();
    let configuration = await onboarding.configuration();
    state.configuration.connectionMode = configuration.connectionMode || 'relay';
    await refreshRelay();
    await refreshVpnConfig();
    browserOptions = await browsers.listBrowsers?.() || [];
    if (!mock && requireRelay && configuration.available) {
      try { await assertRelayConfiguration(await readSessionConfiguration(), undefined, { remote: false }); }
      catch {
        // Upgrading a previously completed direct-ISP installation must return
        // to the ISP form without destroying its endpoint or saved credentials.
        // This is a local comparison; onboarding polling performs no API calls.
        configuration = { ...configuration, available: false, errorCode: 'RELAY_CONFIGURATION_CHANGED' };
      }
    }
    if (configuration.connectionMode === 'vpn-import' && !vpnConfigState.available) configuration = { ...configuration, available: false, errorCode: vpnConfigState.errorCode || 'VPN_NODE_REQUIRED' };
    return { onboarding: { ...preferences, backupExists: Boolean(environmentState.backup) }, configuration, environment: environmentState, startupRecovery: startupRecovery(), relay: { ...relayState, required: requireRelay && !isCompatibilityMode(configuration.connectionMode) }, vpnConfig: vpnConfigState, vpnLatency: publicVpnLatency(), browserOptions };
  }

  async function refreshRelay() {
    const required = requireRelay && !isCompatibilityMode(state.configuration.connectionMode);
    try { relayState = { ...await relayManager.status(), required }; }
    catch (cause) {
      if (!isCompatibilityMode(state.configuration.connectionMode) || !['RELAY_ENROLLMENT_INVALID', 'RELAY_PATH_INVALID', 'RELAY_STORAGE_FAILED'].includes(cause.code)) throw cause;
      relayState = { configured: false, required: false, mock, errorCode: cause.code };
    }
    return relayState;
  }

  async function reminderContext() {
    const bindings = {};
    let subscription = { configured: false };
    try {
      const config = await readSessionConfiguration();
      bindings.isp = hash([config.upstream.type, config.upstream.host.toLowerCase(), config.upstream.port, [...new Set((config.probe.expectedExitIps || []).map(ip => ip.toLowerCase()))].sort()]);
      if (config.connectionMode === 'vpn-compat') bindings.vpn = hash(['external-vpn', bindings.isp]);
    } catch { /* Missing setup means resource dates remain unknown. */ }
    try {
      const record = await vpnConfigStore.load();
      if (record) bindings.vpn = hash([record.id, record.subscription?.url || null]);
      subscription = (await vpnConfigStore.status()).subscription || subscription;
    } catch { /* A reminder never authorizes or repairs a configuration. */ }
    return { license: licensing.status(), subscription, bindings };
  }

  async function remindersStatus() { return serviceReminders.status(await reminderContext()); }

  async function saveReminder(body) {
    if (Object.keys(body).some(key => !['confirm', 'kind', 'expiresOn', 'expectedRevision'].includes(key))) throw error('INPUT_INVALID', '到期提醒包含未知字段', 400);
    confirmed(body); assertStartupRecovered();
    const context = await reminderContext();
    await serviceReminders.save({ kind: body.kind, expiresOn: body.expiresOn, binding: context.bindings[body.kind], ...(body.expectedRevision !== undefined ? { expectedRevision: body.expectedRevision } : {}) });
    return serviceReminders.status(context);
  }

  async function supportReport() {
    if (closing || repairPending) throw error('SERVICE_REPAIRING', '服务正在退出或修复，请稍后保存报告', 503);
    const started = now();
    let result = 'not-running', code = null;
    try {
      await refreshLocal();
      if (state.proxy.running && state.proxy.managed && !state.proxy.requestedStop) {
        result = 'checking';
        await verifyExit({ force: true });
        result = mock ? 'mocked' : 'verified';
      }
    } catch (cause) {
      result = 'failed'; code = Object.hasOwn(ERROR_MESSAGES, cause?.code) ? cause.code : 'OPERATION_FAILED';
      rememberFailure(cause);
    }
    // A failed route must still produce a usable report. Never include raw errors,
    // private configuration, browser identities or unfiltered process metadata.
    let count = 0;
    try { count = (await workspaces.list()).items.length; } catch { /* Optional metadata. */ }
    const report = createSupportReport({ version: options.appVersion, status: { ...publicStatus(), workspaces: { count } }, now });
    return { ...report, run: { chainCheck: result, code, elapsedMs: Math.max(0, now() - started) } };
  }

  async function previewDelivery(body) {
    if (Object.keys(body).some(key => key !== 'text')) throw error('INPUT_INVALID', '交付预览只接受文件内容', 400);
    assertStartupRecovered();
    const delivery = parseCustomerDelivery(body.text);
    const preview = await deliveryImporter.preview(delivery);
    return { ...storePlan('delivery', delivery), preview };
  }

  async function importDelivery(body) {
    if (Object.keys(body).some(key => !['confirm', 'token'].includes(key))) throw error('INPUT_INVALID', '交付导入只接受已预览的确认凭证', 400);
    confirmed(body); assertStartupRecovered();
    const plan = consumePlan('delivery', body.token);
    deliveryRevision = plan.revision;
    const abort = new AbortController(); deliveryAbort = abort;
    try {
      const result = await deliveryImporter.import(plan.payload, { signal: abort.signal });
      if (result.imported) {
        invalidate(); compatibilityState = null; vpnLatencyState = null; vpnLatencyCache = null;
        state.configHash = null; state.sessionConfigHash = null;
        if (result.configuration) state.configuration = result.configuration;
        if (result.vpn) vpnConfigState = result.vpn;
        browserObservation.invalidate();
      }
      return result;
    } finally { if (deliveryAbort === abort) deliveryAbort = null; deliveryRevision = null; state.operation = null; }
  }
  const sameUpstream = (a, b) => Boolean(a && b && a.host.toLowerCase() === b.host.toLowerCase() && a.port === b.port);
  const readSavedSecrets = config => (options.loadSecrets || loadSecrets)(path.resolve(options.secretsPath || path.join(runtimeRoot, 'upstream.secrets.env')), config);
  async function assertRelayConfiguration(config, suppliedSecrets, { remote = true, signal } = {}) {
    checkCanceled(signal);
    if (mock || isCompatibilityMode(config.connectionMode) || (!requireRelay && !config.relay)) return;
    const registered = await relayManager.credentials();
    checkCanceled(signal);
    const secrets = suppliedSecrets || await readSavedSecrets(config);
    checkCanceled(signal);
    if (!config.relay || hash(config.relay) !== hash(registered.relay) || secrets.RELAY_USERNAME !== registered.secrets.RELAY_USERNAME || secrets.RELAY_PASSWORD !== registered.secrets.RELAY_PASSWORD) throw error('RELAY_CONFIGURATION_CHANGED', ERROR_MESSAGES.RELAY_CONFIGURATION_CHANGED);
    if (remote) {
      try {
        const checked = await relayManager.check();
        checkCanceled(signal);
        if (!sameUpstream(checked.upstream, config.upstream)) throw error('RELAY_BINDING_MISMATCH', ERROR_MESSAGES.RELAY_BINDING_MISMATCH);
      } finally { checkCanceled(signal); await refreshRelay(); }
    }
  }
  async function rollbackRelay(binding) {
    if (!binding || sameUpstream(binding.before.upstream, binding.after.upstream)) return;
    try {
      // The temporary verifier has already stopped its owned core. A CONNECT
      // worker may need a short bounded interval to notice the socket closing.
      for (let attempt = 0; attempt < 31; attempt++) {
        const live = await relayManager.check();
        if (live.bindingRevision !== binding.after.bindingRevision) throw error('RELAY_BINDING_CONFLICT', ERROR_MESSAGES.RELAY_BINDING_CONFLICT);
        if (!live.activeTunnels) break;
        if (attempt === 30) throw error('RELAY_IN_USE', ERROR_MESSAGES.RELAY_IN_USE);
        await new Promise(resolve => setTimeout(resolve, 200));
      }
      if (binding.before.upstream) await relayManager.bind(binding.before.upstream, binding.after.bindingRevision);
      else await relayManager.clear(binding.after.bindingRevision);
    } catch { throw error('RELAY_ROLLBACK_REQUIRED', ERROR_MESSAGES.RELAY_ROLLBACK_REQUIRED); }
  }

  async function assertSetupIdle({ allowRetainedLock = false } = {}) {
    const live = await runtime.status({ force: true });
    const browser = await browsers.status();
    if (live.running || browser.running) throw error('SETUP_SESSION_ACTIVE', '请先结束代理和独立浏览器会话，再修改或检测 ISP');
    await refreshNetworkLock();
    if (!allowRetainedLock && runtime.networkLock && (networkLockState.locked || networkLockState.state !== 'unlocked')) throw error('SETUP_NETWORK_LOCKED', '断网锁仍在保护网络，请先明确解除，再修改或检测 ISP');
  }

  function assertSetupRevision(revision) {
    checkCanceled(connectionAttempt?.controller.signal);
    assertStartupRecovered();
    if (closing || revision !== state.revision) throw error('SESSION_CHANGED', ERROR_MESSAGES.SESSION_CHANGED);
  }

  async function verifyCompatibility(input, revision, manualProxy) {
    if (manualProxy !== undefined) validateVpnProxy(manualProxy, input.config.listen.port);
    await assertSetupIdle();
    await runtime.assertCompatibilityReady?.();
    assertSetupRevision(revision);
    const routes = mock ? [{ strategy: 'system', source: 'simulation' }] : await (options.compatibilityRoutes || compatibilityRoutes)({ manualProxy, listenPort: input.config.listen.port });
    compatibilityState = { status: 'checking', attempts: [], observedAt: timestamp(), scope: '验证通过 ISP 的请求路径，不证明外部 VPN 身份或其他应用设置' };
    for (const route of routes) {
      assertSetupRevision(revision);
      state.operation = { stage: 'detecting-network', message: route.strategy === 'system' ? '正在测试系统网络能否通过 ISP 出口…' : `正在测试本地 ${route.strategy === 'socks-proxy' ? 'SOCKS5' : 'HTTP'} VPN 代理及 ISP 出口…`, at: timestamp() };
      diagnostic({ code: 'VPN_COMPAT_NETWORK_CHECK', operation: `detecting-${route.strategy}` });
      try {
        const result = await setupVerifier.verify({ ...input, ...(route.vpnProxy ? { vpnProxy: route.vpnProxy } : {}) });
        assertSetupRevision(revision);
        compatibilityState = { ...compatibilityState, status: mock ? 'mocked' : 'verified', strategy: route.strategy, source: ['manual', 'system-network', 'windows-proxy', 'proxy-environment', 'simulation'].includes(route.source) ? route.source : 'unknown', ...(route.vpnProxy ? { proxy: { ...route.vpnProxy } } : {}), attempts: [...compatibilityState.attempts, { strategy: route.strategy, status: 'verified' }], observedAt: timestamp() };
        diagnostic({ code: 'VPN_COMPAT_NETWORK_VERIFIED', operation: `detecting-${route.strategy}` });
        return { result, vpnProxy: route.vpnProxy };
      } catch (cause) {
        assertSetupRevision(revision);
        const code = failureCode(cause);
        compatibilityState.attempts.push({ strategy: route.strategy, status: 'failed', errorCode: code, ...probeDiagnostic(cause) });
        diagnostic({ code, operation: `detecting-${route.strategy}`, diagnostic: cause.diagnostic });
        if (cause.code !== 'SETUP_CHECK_FAILED') { compatibilityState.status = 'failed'; throw cause; }
      }
    }
    compatibilityState.status = 'failed';
    diagnostic({ code: 'VPN_COMPAT_NO_ROUTE', operation: 'detecting-network' });
    throw error('VPN_COMPAT_NO_ROUTE', ERROR_MESSAGES.VPN_COMPAT_NO_ROUTE);
  }

  async function verifyImportedConfiguration(input, revision, { forceLatency = false, firstVerified = false } = {}) {
    await assertSetupIdle();
    await runtime.assertCompatibilityReady?.();
    assertSetupRevision(revision);
    const profile = await vpnConfigStore.status();
    const profileId = profile.id;
    const allCandidates = await vpnConfigStore.candidates();
    if (!allCandidates.length) throw error('VPN_NODE_REQUIRED', ERROR_MESSAGES.VPN_NODE_REQUIRED);
    const snapshot = allCandidates.map(node => ({ index: node.index, hash: hash(node.outbound) }));
    const cacheKey = expectedExitIps => hash({ profileId, selectedIndex: profile.selectedIndex, nodes: snapshot,
      config: { ...input.config, probe: { ...input.config.probe, expectedExitIps } }, secrets: input.secrets });
    const expected = input.config.probe.expectedExitIps;
    const cached = !forceLatency && vpnLatencyCache && now() - vpnLatencyCache.createdAt < VPN_LATENCY_TTL
      && vpnLatencyCache.key === cacheKey(expected.length ? expected : vpnLatencyCache.expectedExitIps);
    const history = vpnLatencyState?.profileId === profileId ? vpnLatencyState.results.filter(item => item.status === 'verified').map(item => item.nodeIndex) : [];
    let candidates;
    if (cached) {
      const ranks = vpnLatencyCache.ranks, shortlist = vpnLatencyCache.shortlistIndices || ranks;
      candidates = allCandidates.filter(node => shortlist.includes(node.index)).sort((a, b) => (ranks.indexOf(a.index) < 0 ? Infinity : ranks.indexOf(a.index)) - (ranks.indexOf(b.index) < 0 ? Infinity : ranks.indexOf(b.index)) || a.index - b.index).slice(0, 3);
      vpnLatencyState.status = 'checking';
      vpnLatencyState.screening = { scope: 'cached-shortlist', durationMs: 0, screened: 0, total: allCandidates.length, results: [], complete: true };
    } else {
      vpnLatencyCache = null;
      vpnLatencyState = { profileId, status: 'checking', phase: 'screening', scope: 'node-isp-https', observedAt: timestamp(), results: [], recommendedNodeIndex: null,
        candidateCount: allCandidates.length, shortlistSize: 0, shortlistedNodeIndices: [], verifiedEligible: 0, tested: 0, total: 0 };
      if (mock || profile.selectedIndex !== null) {
        candidates = allCandidates.slice(0, profile.selectedIndex !== null ? 1 : 3);
        vpnLatencyState.screening = { scope: mock ? 'simulation' : 'selected-node', durationMs: 0, screened: 0, total: allCandidates.length, results: [], complete: true };
      } else {
        state.operation = { stage: 'screening-imported-nodes', message: '正在并发轻筛节点 TCP 可达性，随后只验证前三候选的 ISP 链路…', at: timestamp() };
        const shortlist = await (options.shortlistImportedNodes || screenImportedNodes)(allCandidates, { listenPort: input.config.listen.port, history, force: forceLatency, signal: input.signal,
          onProgress: screening => { vpnLatencyState.screening = screening; vpnLatencyState.observedAt = timestamp(); } });
        assertSetupRevision(revision);
        candidates = shortlist.nodes.slice(0, 3);
        vpnLatencyState.screening = shortlist.screening;
      }
    }
    vpnLatencyState.phase = 'verifying'; vpnLatencyState.candidateCount = allCandidates.length;
    vpnLatencyState.shortlistSize = candidates.length; vpnLatencyState.shortlistedNodeIndices = candidates.map(node => node.index); vpnLatencyState.total = candidates.length;
    const deadline = now() + (options.importedProbeBudgetMs || 180_000);
    compatibilityState = { status: 'checking', strategy: 'imported-node', attempts: [], observedAt: timestamp(), scope: '配置节点经 ISP 的本地 HTTP 代理；外部 VPN 关闭情况无法独立证明' };
    const retryable = ['SETUP_CHECK_FAILED', 'VPN_NODE_RESOLVE_FAILED', 'CORE_START_FAILED'];
    const verified = [];
    const assertNode = async node => {
      assertSetupRevision(revision);
      if ((await vpnConfigStore.status()).id !== profileId || !(await vpnConfigStore.candidates()).some(candidate => candidate.index === node.index && hash(candidate.outbound) === hash(node.outbound))) {
        compatibilityState.status = 'failed'; vpnLatencyCache = null;
        if (vpnLatencyState) { vpnLatencyState.status = 'failed'; vpnLatencyState.recommendedNodeIndex = null; }
        throw error('VPN_IMPORT_CONFLICT', ERROR_MESSAGES.VPN_IMPORT_CONFLICT);
      }
    };
    const recordLatency = observation => {
      if (!vpnLatencyState) return;
      const previous = vpnLatencyState.results.findIndex(item => item.nodeIndex === observation.nodeIndex);
      if (previous >= 0) vpnLatencyState.results[previous] = observation;
      else vpnLatencyState.results.push(observation);
      vpnLatencyState.tested = vpnLatencyState.results.length; vpnLatencyState.observedAt = timestamp();
      vpnLatencyState.verifiedEligible = vpnLatencyState.results.filter(item => item.status === 'verified').length;
    };
    for (const node of candidates) {
      await assertNode(node);
      if (now() >= deadline) break;
      state.operation = { stage: 'checking-imported-node', message: `正在验证候选 ${compatibilityState.attempts.length + 1}/${candidates.length}：节点 ${node.index} → ISP → HTTPS…`, at: timestamp() };
      try {
        // Ranking measures only the two fixed ISP HTTPS sources. Expensive quality
        // inspection runs once, through the eventual selected and reverified node.
        const { inspect, ...verificationInput } = input;
        const pinned = verified[0]?.result.expectedExitIps;
        const result = await setupVerifier.verify({ ...verificationInput, config: pinned ? { ...input.config, probe: { ...input.config.probe, expectedExitIps: pinned } } : input.config, vpnNode: node.outbound });
        await assertNode(node);
        const latencyMs = !mock && !result.mock && Number.isFinite(result.latencyMs) && result.latencyMs >= 0 && result.latencyMs <= 120_000 ? Math.max(1, Math.round(result.latencyMs)) : null;
        compatibilityState.attempts.push({ nodeIndex: node.index, status: 'verified', latencyMs });
        recordLatency({ nodeIndex: node.index, status: 'verified', latencyMs });
        verified.push({ node, result, latencyMs });
        if (cached || firstVerified) break;
      } catch (cause) {
        assertSetupRevision(revision);
        const code = failureCode(cause);
        compatibilityState.attempts.push({ nodeIndex: node.index, status: 'failed', errorCode: code });
        recordLatency({ nodeIndex: node.index, status: 'failed', latencyMs: null, errorCode: code });
        diagnostic({ code, operation: 'checking-imported-node', diagnostic: cause.diagnostic });
        if (!retryable.includes(cause.code)) {
          compatibilityState.status = 'failed'; vpnLatencyCache = null;
          if (vpnLatencyState) { vpnLatencyState.status = 'failed'; vpnLatencyState.recommendedNodeIndex = null; }
          throw cause;
        }
      }
    }
    if (verified.length) {
      verified.sort((a, b) => (a.latencyMs ?? Infinity) - (b.latencyMs ?? Infinity) || a.node.index - b.node.index);
      const winner = verified[0];
      await assertNode(winner.node);
      let result = winner.result;
      if (input.inspect) {
        try {
          result = await setupVerifier.verify({ ...input, config: { ...input.config, probe: { ...input.config.probe, expectedExitIps: result.expectedExitIps } }, vpnNode: winner.node.outbound });
          await assertNode(winner.node);
        } catch (cause) {
          compatibilityState.status = 'failed'; vpnLatencyCache = null;
          if (vpnLatencyState) { vpnLatencyState.status = 'failed'; vpnLatencyState.recommendedNodeIndex = null; }
          throw cause;
        }
      }
      if (!cached) {
        vpnLatencyState.status = mock || verified.every(item => item.result.mock) ? 'mocked' : vpnLatencyState.tested < allCandidates.length ? 'partial' : 'complete';
        vpnLatencyState.recommendedNodeIndex = winner.node.index;
        vpnLatencyState.results.sort((a, b) => (a.status === 'verified' ? a.latencyMs ?? Infinity : Infinity) - (b.status === 'verified' ? b.latencyMs ?? Infinity : Infinity) || a.nodeIndex - b.nodeIndex);
        vpnLatencyState.observedAt = timestamp();
        vpnLatencyCache = { key: cacheKey(result.expectedExitIps), createdAt: now(), selectedIndex: profile.selectedIndex, nodeKey: hash(snapshot),
          configHash: hash({ ...input.config, probe: { ...input.config.probe, expectedExitIps: result.expectedExitIps } }),
          expectedExitIps: [...result.expectedExitIps], ranks: verified.map(item => item.node.index), shortlistIndices: candidates.map(item => item.index) };
      } else {
        vpnLatencyState.status = mock || result.mock ? 'mocked' : vpnLatencyState.tested < allCandidates.length ? 'partial' : 'complete';
        vpnLatencyState.recommendedNodeIndex = winner.node.index;
        vpnLatencyState.results.sort((a, b) => (a.status === 'verified' ? a.latencyMs ?? Infinity : Infinity) - (b.status === 'verified' ? b.latencyMs ?? Infinity : Infinity) || a.nodeIndex - b.nodeIndex);
        vpnLatencyCache.ranks = [winner.node.index, ...vpnLatencyState.results.filter(item => item.status === 'verified' && item.nodeIndex !== winner.node.index).map(item => item.nodeIndex)];
      }
      compatibilityState = { ...compatibilityState, status: mock || result.mock ? 'mocked' : 'verified', winningNodeIndex: winner.node.index, observedAt: timestamp() };
      diagnostic({ code: 'VPN_IMPORT_VERIFIED', operation: 'checking-imported-node' });
      return { result, vpnNode: winner.node.outbound };
    }
    compatibilityState.status = 'failed';
    vpnLatencyCache = null;
    if (vpnLatencyState) { vpnLatencyState.status = 'failed'; vpnLatencyState.recommendedNodeIndex = null; }
    throw error('VPN_IMPORT_NO_ROUTE', ERROR_MESSAGES.VPN_IMPORT_NO_ROUTE);
  }

  async function saveConfiguration(body, revision) {
    assertSetupRevision(revision);
    await assertSetupIdle();
    state.operation = { stage: 'saving-isp', message: '正在验证 ISP 地址及两个独立出口，再保存配置', at: timestamp() };
    let relayBinding = null; let committed = false;
    try {
      const { vpnProxy, ...configurationBody } = body;
      const configuration = await onboarding.saveConfiguration(configurationBody, { prepareConfiguration: async input => {
        if (input.config.connectionMode === 'vpn-import') {
          if (vpnProxy !== undefined) throw error('VPN_PROXY_INVALID', ERROR_MESSAGES.VPN_PROXY_INVALID);
          await assertImportedConfiguration(input.config);
          return input;
        }
        if (input.config.connectionMode === 'vpn-compat') {
          if (vpnProxy !== undefined) validateVpnProxy(vpnProxy, input.config.listen.port);
          return input;
        }
        if (vpnProxy !== undefined) throw error('VPN_PROXY_INVALID', ERROR_MESSAGES.VPN_PROXY_INVALID);
        if (mock || (!requireRelay && !input.config.relay)) return input;
        const registered = await relayManager.credentials();
        return { config: { ...input.config, relay: registered.relay }, secrets: { ...input.secrets, ...registered.secrets } };
      }, verifyConfiguration: async input => {
        assertSetupRevision(revision);
        if (input.config.connectionMode === 'vpn-import') return (await verifyImportedConfiguration(input, revision)).result;
        if (input.config.connectionMode === 'vpn-compat') return (await verifyCompatibility(input, revision, vpnProxy)).result;
        if (input.config.relay && !mock) {
          const before = await relayManager.check();
          const after = await relayManager.bind({ host: input.config.upstream.host, port: input.config.upstream.port }, before.bindingRevision);
          relayBinding = { before, after };
        }
        const checked = await setupVerifier.verify(input);
        assertSetupRevision(revision);
        return checked;
      } });
      committed = true;
      assertSetupRevision(revision);
      if (!isCompatibilityMode(configuration.connectionMode)) compatibilityState = null;
      invalidate(); state.lastError = null; state.phase = 'idle';
      state.configHash = null; state.sessionConfigHash = null;
      state.configuration = configuration;
      return { configuration, ...await refreshDiagnosticsAfterSave() };
    } catch (cause) {
      if (!committed) {
        try { await rollbackRelay(relayBinding); }
        catch (rollbackError) { rememberFailure(rollbackError); throw rollbackError; }
      }
      rememberFailure(cause); throw cause;
    } finally { state.operation = null; }
  }

  async function checkQuality(revision, body = {}) {
    assertSetupRevision(revision);
    await assertSetupIdle();
    if (!(await onboarding.configuration()).available) throw error('ONBOARDING_CONFIGURATION_REQUIRED', ERROR_MESSAGES.ONBOARDING_CONFIGURATION_REQUIRED);
    state.operation = { stage: 'checking-quality', message: '正在通过 ISP 检测三个站点的连通性与响应时间', at: timestamp() };
    try {
      const config = await readSessionConfiguration();
      if (config.connectionMode !== 'vpn-compat' && body.vpnProxy !== undefined) throw error('VPN_PROXY_INVALID', ERROR_MESSAGES.VPN_PROXY_INVALID);
      const secrets = mock ? {} : await readSavedSecrets(config);
      await assertRelayConfiguration(config, secrets);
      const input = { config, secrets, inspect: input => qualityReports.run(input) };
      const result = config.connectionMode === 'vpn-import' ? (await verifyImportedConfiguration(input, revision)).result : config.connectionMode === 'vpn-compat' ? (await verifyCompatibility(input, revision, body.vpnProxy)).result : await setupVerifier.verify(input);
      assertSetupRevision(revision);
      return result.inspection;
    } finally { state.operation = null; }
  }

  async function exportDiagnostics() {
    let config = null;
    try { config = await readSessionConfiguration(); }
    catch (cause) { if (!['CONFIG_READ_FAILED', 'CONFIG_INVALID', 'EXPECTED_EXIT_REQUIRED'].includes(cause.code)) throw cause; }
    if (!isCompatibilityMode(config?.connectionMode) && (await refreshRelay()).configured) {
      // Only public transport metadata enters the manifest builder. It derives
      // the certificate fingerprint and omits the PEM and both account layers.
      config = { ...config, relay: (await relayManager.credentials()).relay };
    }
    return (options.exportDiagnostics || exportChainDiagnostics)({ runtimeRoot,
      sourceDirectory: options.diagnosticsSourceDirectory, config,
      corePath: options.corePath || path.join(backendRoot, '.cache/core/sing-box-1.14.2-windows-amd64/sing-box.exe'),
      appPath: options.recoveryAppPath, lastFailure: state.lastError, mock });
  }

  async function refreshDiagnosticsAfterSave() {
    try {
      const exported = await exportDiagnostics();
      return { diagnosticsExported: true, diagnostics: { directory: exported.directory, files: exported.files, mock: exported.mock } };
    } catch {
      // Diagnostic artifacts are auxiliary: their failure must never roll back
      // an already committed ISP pair or its successful remote CAS binding.
      return { diagnosticsExported: false, diagnosticsErrorCode: 'DIAGNOSTICS_EXPORT_FAILED' };
    }
  }

  async function readSessionConfiguration() {
    let config = await runtime.readConfig();
    if (mock) {
      const saved = await onboarding.configuration();
      if (isCompatibilityMode(saved.connectionMode) || isCompatibilityMode(config.connectionMode)) {
        config = { ...config, connectionMode: saved.connectionMode || 'relay' };
        if (isCompatibilityMode(config.connectionMode)) delete config.relay;
      }
    }
    return config;
  }

  async function loadConfiguration() {
    assertStartupRecovered();
    const revision = state.revision, generation = networkGeneration;
    const config = await readSessionConfiguration();
    if (revision !== state.revision || generation !== networkGeneration) throw error('SESSION_CHANGED', ERROR_MESSAGES.SESSION_CHANGED);
    const fingerprint = hash(config);
    if (vpnLatencyCache && vpnLatencyCache.configHash !== fingerprint) { vpnLatencyCache = null; vpnLatencyState = null; }
    if (state.configHash && state.configHash !== fingerprint) invalidate();
    state.configHash = fingerprint;
    state.configuration = { available: true, pinned: config.probe.expectedExitIps.length > 0, connectionMode: config.connectionMode || 'relay' };
    if (!state.proxy.running) state.proxy.port = config.listen.port;
    return { config, fingerprint };
  }

  async function refreshLocal({ force = false, ownedOnly = false, includeBrowser = true } = {}) {
    assertStartupRecovered();
    const revision = state.revision, generation = networkGeneration;
    const unchanged = () => { if (revision !== state.revision || generation !== networkGeneration) throw error('SESSION_CHANGED', ERROR_MESSAGES.SESSION_CHANGED); };
    const running = ownedOnly && runtime.inspectOwnedState ? await runtime.inspectOwnedState() : await runtime.status({ force: force || ownedOnly });
    unchanged();
    if (running.inspectionSuperseded === true) throw error('SESSION_CHANGED', ERROR_MESSAGES.SESSION_CHANGED);
    if (!running.networkLock) { await refreshNetworkLock({ force, cached: ownedOnly }); unchanged(); }
    else networkLockState = { ...running.networkLock, status: running.networkLock.status || running.networkLock.state };
    if (!state.initialized) {
      state.initialized = true;
      if (!state.revision) state.proxy.requestedStop = !running.running;
      state.sessionConfigHash = running.configHash || null;
    }
    if ((!running.running || state.proxy.sessionId && running.sessionId !== state.proxy.sessionId) && state.proxy.running) invalidate();
    state.proxy.running = Boolean(running.running);
    state.proxy.managed = Boolean(running.managed);
    state.proxy.mode = running.mode || 'http';
    state.proxy.routingMode = running.routingMode || null;
    state.proxy.coreObservation = running.coreObservation || null;
    state.proxy.protections = running.protections || null;
    state.proxy.compatibility = running.compatibility || null;
    state.proxy.vpnNodeHash = running.vpnNodeHash || null;
    state.proxy.sessionId = running.sessionId || null;
    if (running.trafficBlocked === true) {
      state.proxy.trafficBlocked = true; state.proxy.trafficHoldStatus = running.trafficBlockConfirmed === true ? 'blocked' : 'failed'; state.proxy.requestedStop = true;
      networkLifecycle = { state: 'blocked', reason: 'retained-traffic-gate' };
    }
    if (running.port) state.proxy.port = running.port;
    if (includeBrowser) {
      const currentRevision = state.revision;
      const browser = await browsers.status();
      if (currentRevision !== state.revision || generation !== networkGeneration) throw error('SESSION_CHANGED', ERROR_MESSAGES.SESSION_CHANGED);
      state.browser = browser;
    }
    if (running.running && running.mode === 'tun' && running.tunReady === false) throw error('TUN_NOT_READY', ERROR_MESSAGES.TUN_NOT_READY);
    if (state.proxy.exit && now() - state.proxy.exit.checkedAt > EXIT_TTL) { state.proxy.exit = null; state.proxy.systemExit = null; }
    if (!state.proxy.running || state.proxy.requestedStop) { state.proxy.exit = null; state.proxy.systemExit = null; }
    return running;
  }

  function publicStatus() {
    const enabled = state.proxy.running && !state.proxy.requestedStop;
    const observed = enabled && networkLifecycle.state === 'stable' && freshObservation(state.proxy.exit, state.configHash) ? state.proxy.exit : null;
    const exit = observed ? { ip: observed.ip, observedAt: observed.observedAt } : null;
    const exitStatus = observed ? (mock ? 'mocked' : 'verified') : 'unverified';
    const systemExit = observed && freshObservation(state.proxy.systemExit, state.configHash) && state.proxy.systemExit;
    const systemNetwork = { status: state.proxy.mode !== 'tun' ? 'not-applicable' : !enabled ? 'offline' : systemExit ? (mock ? 'mocked' : 'verified') : 'unverified', ...(systemExit ? { ip: systemExit.ip, observedAt: systemExit.observedAt } : {}) };
    const environmentStatus = environmentState.optimization?.status || 'not-requested';
    const environmentIncomplete = ['partial', 'failed', 'recovery-required'].includes(environmentStatus) || ['recovery-required', 'conflict', 'failed'].includes(environmentState.status);
    return {
      service: { status: 'ready', version: '2.0.0', mock }, phase: state.phase, operation: state.operation, license: licensing.status(),
      statusRead: { state: statusRefresh ? 'checking' : queuedOperations ? 'busy' : 'cached', checkedAt: statusCheckedAt,
        connectionChecked: Boolean(observed && !queuedOperations && !startupRecoveryError && !blockPending && !repairPending && state.proxy.managed && (state.proxy.mode !== 'tun' || systemExit)) },
      health: { ...healthState },
      startupRecovery: startupRecovery(), relay: { ...relayState, required: requireRelay && !isCompatibilityMode(state.configuration.connectionMode) }, vpnConfig: vpnConfigState, vpnLatency: publicVpnLatency(), compatibility: compatibilityState,
      configuration: state.configuration, revision: state.revision, blockPending, networkLifecycle: { ...networkLifecycle }, capabilities: proxyCapabilities(),
      connectionCancellation: { active: Boolean(connectionAttempt), requested: connectionAttempt?.controller.signal.aborted === true },
      proxy: { enabled, running: state.proxy.running, managed: state.proxy.managed, requestedStop: state.proxy.requestedStop, trafficBlocked: state.proxy.trafficBlocked === true, trafficHoldStatus: state.proxy.trafficHoldStatus || null, port: state.proxy.port, endpoint: `127.0.0.1:${state.proxy.port}`, mode: state.proxy.mode || 'tun', routingMode: state.proxy.routingMode || null, coreObservation: state.proxy.coreObservation, connectionMode: state.configuration.connectionMode || 'relay', compatibility: state.proxy.compatibility, exitStatus, exit, exitIp: exit?.ip || null, systemNetwork, protections: state.proxy.protections },
      applicationProxy: { ...applicationGateway.status(), corePort: state.proxy.port, coverage: applicationCoverage(), scope: '本机与内网直连；公网经已核验的节点与 ISP；仅对显式使用此入口的应用生效；OAuth 唤起的普通浏览器需另有系统保护' },
      browser: state.browser, browserOptions, browserObservation: browserObservation?.snapshot() || { status: 'unverified' }, fingerprintInstall: { ...fingerprintInstall }, exitStatus, lastError: state.lastError,
      connectionResult: { status: state.proxy.trafficHoldStatus === 'failed' ? 'pause-unconfirmed' : state.proxy.trafficHoldStatus === 'pending' ? 'pausing' : state.proxy.trafficHoldStatus === 'blocked' ? 'paused' : !enabled ? 'disconnected' : !observed ? 'awaiting-verification' : environmentIncomplete ? 'connected-with-warnings' : 'connected', environmentStatus, message: state.proxy.trafficHoldStatus === 'failed' ? '未能确认阻断转发；TUN 保持运行，但不能证明传输已停止。请查看诊断或明确结束连接。' : state.proxy.trafficHoldStatus === 'pending' ? '正在暂停转发；TUN 保持运行，阻断结果待确认。' : state.proxy.trafficHoldStatus === 'blocked' ? '代理转发已暂停，TUN 保持接管；恢复普通网络需明确结束连接。' : !enabled ? '代理未连接' : !observed ? '代理核心运行中，当前出口待重新核验' : environmentIncomplete ? '代理已连接，但环境优化未完成，请查看环境提示。' : '代理已连接' },
      environment: environmentState, networkLock: networkLockState, report: latestReport ? { ...latestReport, stale: reportRevision !== state.revision || !enabled || !observed || latestReport.exit?.ip !== observed.ip || now() - Date.parse(latestReport.generatedAt) > EXIT_TTL } : null,
      protection: { explicitProxy: enabled ? (mock ? 'mocked' : 'available') : 'offline', ispExit: exitStatus, tun: enabled && state.proxy.mode === 'tun' ? (mock ? 'mocked' : 'configured') : 'offline', systemWide: systemNetwork.status === 'verified' ? 'default-network-verified' : 'not-verified', killSwitch: networkLockVerified() && !mock, systemProtected: applicationCoverage().systemProtected,
        statement: networkLockVerified() ? '断网锁已保持：停止或核心异常后继续阻断普通直连。解除断网锁需明确确认。'
          : networkLockState.developmentPaused ? '新断网锁开发已暂停，连接与应用接入不依赖它；旧锁的网络修复入口保留。未开锁时，代理断开后普通应用可能恢复直连。'
          : state.configuration.connectionMode === 'vpn-import' ? state.proxy.mode === 'tun' ? '全局 TUN → 导入节点 → ISP，无需运行外部 VPN；核验出口后可手动开启仅放行受管核心和固定节点端点的断网锁。' : '导入节点 → ISP，默认使用应用分流，无需运行外部 VPN；仅显式使用代理入口的应用受到覆盖，普通浏览器和 OAuth 跳转需要已核验的全局 TUN；断网锁可选。'
          : state.configuration.connectionMode === 'vpn-compat' ? '兼容模式只提供本地 HTTP 代理。外部 VPN 需保持开启；此模式不提供 TUN 或断网锁。' : '断网锁未开启。TUN 连接并验证出口后，可在保护面板手动开启。' },
      generatedAt: timestamp(),
    };
  }

  function applicationCoverage() {
    const mode = state.proxy.mode === 'tun' ? 'tun' : 'http';
    const active = state.proxy.running && state.proxy.managed && !state.proxy.requestedStop && !blockPending && !repairPending && networkLifecycle.state === 'stable';
    const systemExitVerified = Boolean(!mock && active && mode === 'tun' && state.proxy.protections?.systemRouting
      && freshObservation(state.proxy.exit, state.configHash) && freshObservation(state.proxy.systemExit, state.configHash));
    const killSwitch = Boolean(!mock && networkLockVerified() && networkLockState.persistent && !networkLockState.mock && state.proxy.protections?.killSwitch);
    return { mode, systemExitVerified, killSwitch, systemProtected: systemExitVerified && killSwitch };
  }

  async function status() {
    // Do not read either half of a configuration pair until its save journal
    // has recovered. Polling must not silently retry a failed startup recovery.
    if (startupRecoveryError) return publicStatus();
    try {
      await refreshLocal();
      const snapshot = await loadConfiguration();
      await refreshRelay();
      await refreshVpnConfig();
      if (state.proxy.running && state.sessionConfigHash && snapshot.fingerprint !== state.sessionConfigHash) throw error('PROXY_CONFIG_CHANGED', ERROR_MESSAGES.PROXY_CONFIG_CHANGED);
      if (state.proxy.running) await assertRelayConfiguration(snapshot.config, undefined, { remote: false });
      await assertImportedConfiguration(snapshot.config);
    } catch (cause) {
      if (cause.code === 'SESSION_CHANGED') return publicStatus();
      diagnostic({ code: cause.code, operation: 'checking-local-status', diagnostic: cause.diagnostic });
      if (cause.code?.startsWith('CONFIG')) state.configuration = { available: false };
      if (OBSERVATION_FAILURES.has(cause.code) && state.proxy.running && state.proxy.managed && !state.proxy.requestedStop) {
        rememberFailure(cause); healthState = { state: 'degraded', checkedAt: timestamp(), errorCode: state.lastError.code };
      } else if (state.proxy.running || state.browser.running) await blockFailedSession(cause);
      else { invalidate(); state.proxy.requestedStop = true; rememberFailure(cause); }
    }
    statusCheckedAt = timestamp();
    return { ...publicStatus(), statusRead: { state: 'fresh', checkedAt: statusCheckedAt } };
  }

  async function assertActive(allowStopping = false, allowNetworkRefresh = false) {
    const generation = networkGeneration;
    assertStartupRecovered();
    if (!allowNetworkRefresh && ['suspended', 'checking', 'unverified'].includes(networkLifecycle.state)) throw error('NETWORK_RECHECK_REQUIRED', '网络发生变化，当前出口租约已撤销；请等待核验或重新连接');
    await refreshLocal({ ownedOnly: true, includeBrowser: false });
    const revision = state.revision;
    if (state.proxy.requestedStop && !allowStopping) throw error('PROXY_STOPPED', ERROR_MESSAGES.PROXY_STOPPED);
    if (!state.proxy.running || !state.proxy.managed) throw error('PROXY_OFFLINE', ERROR_MESSAGES.PROXY_OFFLINE);
    const snapshot = await loadConfiguration();
    if (state.sessionConfigHash && state.sessionConfigHash !== snapshot.fingerprint) throw error('PROXY_CONFIG_CHANGED', ERROR_MESSAGES.PROXY_CONFIG_CHANGED);
    if (state.proxy.port !== snapshot.config.listen.port) throw error('PROXY_CONFIG_CHANGED', ERROR_MESSAGES.PROXY_CONFIG_CHANGED);
    if (!snapshot.config.probe.expectedExitIps.length) throw error('EXPECTED_EXIT_REQUIRED', ERROR_MESSAGES.EXPECTED_EXIT_REQUIRED);
    await assertRelayConfiguration(snapshot.config, undefined, { remote: false });
    await assertImportedConfiguration(snapshot.config);
    assertRevision(revision, allowStopping);
    if (generation !== networkGeneration) throw error('SESSION_CHANGED', ERROR_MESSAGES.SESSION_CHANGED);
    if (!allowNetworkRefresh && networkLifecycle.state !== 'stable') throw error('NETWORK_RECHECK_REQUIRED', ERROR_MESSAGES.NETWORK_RECHECK_REQUIRED);
    return snapshot;
  }

  function assertRevision(revision, allowStopping = false) {
    checkCanceled(connectionAttempt?.controller.signal);
    if (closing || revision !== state.revision || (state.proxy.requestedStop && !allowStopping)) throw error('SESSION_CHANGED', ERROR_MESSAGES.SESSION_CHANGED);
  }

  async function blockFailedSession(cause) {
    diagnostic({ code: cause?.code, operation: 'blocking-session', diagnostic: cause?.diagnostic });
    invalidate(); state.proxy.requestedStop = true; rememberFailure(cause);
    if (state.proxy.mode === 'tun' && state.proxy.running && state.proxy.managed && runtime.holdTraffic) {
      await suspendPaidSession(cause); return;
    }
    blockPending = true;
    try {
      await runtime.stop();
      state.proxy.running = false; state.proxy.managed = false;
      await refreshNetworkLock({ cached: true });
      blockPending = false;
    } catch (stopError) {
      rememberFailure(stopError);
      // If the owned gateway cannot be stopped, try the normal browser close;
      // retain the pending block and retry without ever killing unknown PIDs.
      try { await browsers.close(); state.browser = await browsers.status(); } catch {}
    }
  }

  function verifyExit(settings = {}) {
    const { force = false, allowStopping = false, allowNetworkRefresh = false } = settings;
    const key = JSON.stringify([exitBinding(state.configHash), networkGeneration, allowNetworkRefresh]);
    const currentProof = freshObservation(state.proxy.exit, state.configHash) && (state.proxy.mode !== 'tun' || freshObservation(state.proxy.systemExit, state.configHash));
    if (exitVerification?.key === key && (force || !currentProof)) {
      const reading = exitVerification;
      return reading.promise.then(result => { assertRevision(reading.revision, allowStopping); return result; });
    }
    if (!force && currentProof) return verifyExitNow(settings);
    const reading = { key, revision: state.revision, promise: verifyExitNow(settings) };
    exitVerification = reading;
    void reading.promise.finally(() => { if (exitVerification === reading) exitVerification = null; }).catch(() => {});
    return reading.promise;
  }

  async function verifyExitNow({ allowStopping = false, force = false, allowNetworkRefresh = false, background = false } = {}) {
    const signal = sessionAbort.signal;
    if (signal.aborted && !connectionAttempt && signal.reason?.code === 'CONNECTION_CANCELED') throw error('PROXY_STOPPED', ERROR_MESSAGES.PROXY_STOPPED);
    checkCanceled(signal);
    const networkReadGeneration = networkGeneration;
    const session = JSON.stringify([state.proxy.sessionId, state.sessionConfigHash, state.proxy.port, state.proxy.mode]);
    let revision = state.revision;
    let result, systemResult, config, fingerprint;
    try {
      ({ config, fingerprint } = await assertActive(allowStopping, allowNetworkRefresh));
      if (networkReadGeneration !== networkGeneration) throw error('SESSION_CHANGED', ERROR_MESSAGES.SESSION_CHANGED);
      // assertActive may invalidate a stale configuration. Use the current
      // revision for this probe; an explicit stop still changes it afterward.
      revision = state.revision;
      assertRevision(revision, allowStopping);
      if (!force && freshObservation(state.proxy.exit, fingerprint)
        && (state.proxy.mode !== 'tun' || freshObservation(state.proxy.systemExit, fingerprint))) {
        const observed = state.proxy.exit;
        return { id: 'exit-ip', label: '指定 ISP 出口', status: mock ? 'mocked' : 'verified', exitIp: observed.ip,
          elapsedMs: observed.elapsedMs, observedAt: observed.observedAt, reused: true,
          scope: mock ? '离线模拟，无实际网络验证' : '复用当前受管会话仍在有效期内的 ISP 出口核验' };
      }
      // A dormant optional lock does not require a new Windows firewall read
      // for every application action. Active locks still receive full checks.
      if (force && networkLockState.locked && runtime.networkLock) {
        await refreshNetworkLock({ force: true });
        assertRevision(revision, allowStopping);
        if (networkLockState.inspectionFailed || networkLockState.state !== 'locked') throw error('NETWORK_LOCK_INSPECTION_FAILED', ERROR_MESSAGES.NETWORK_LOCK_INSPECTION_FAILED);
      }
      result = mock ? { ok: true, status: 'verified', exitIp: config.probe.expectedExitIps[0], elapsedMs: 0 } : await cancelableRead(probeExit(config, config.listen.port, { signal }), signal);
      assertRevision(revision, allowStopping);
      if (!result.ok || result.status !== 'verified') throw error('EXIT_UNVERIFIED', ERROR_MESSAGES.EXIT_UNVERIFIED);
      if (state.proxy.mode === 'tun') {
        const live = runtime.inspectOwnedState ? await runtime.inspectOwnedState() : await runtime.status({ force: true });
        assertRevision(revision, allowStopping);
        if (live.inspectionSuperseded === true) throw error('SESSION_CHANGED', ERROR_MESSAGES.SESSION_CHANGED);
        if (!live.running || !live.managed || live.port !== config.listen.port) throw error('PROXY_OFFLINE', ERROR_MESSAGES.PROXY_OFFLINE);
        if (live.mode === 'tun' && live.tunReady === false) throw error('TUN_NOT_READY', ERROR_MESSAGES.TUN_NOT_READY);
        diagnostic({ code: 'SYSTEM_NETWORK_CHECK', operation: 'verifying-system-network' });
        systemResult = mock ? result : await cancelableRead(probeSystem(config, { signal }), signal);
        assertRevision(revision, allowStopping);
        if (!systemResult.ok || systemResult.status !== 'verified' || !equalIp(systemResult.exitIp, result.exitIp)) throw error('SYSTEM_EXIT_MISMATCH', ERROR_MESSAGES.SYSTEM_EXIT_MISMATCH);
      }
      const latest = await loadConfiguration();
      if (latest.fingerprint !== fingerprint) throw error('PROXY_CONFIG_CHANGED', ERROR_MESSAGES.PROXY_CONFIG_CHANGED);
      assertRevision(revision, allowStopping);
      const live = runtime.inspectOwnedState ? await runtime.inspectOwnedState() : await runtime.status({ force: true });
      if (live.networkLock) networkLockState = { ...live.networkLock, status: live.networkLock.status || live.networkLock.state };
      assertRevision(revision, allowStopping);
      if (live.inspectionSuperseded === true) throw error('SESSION_CHANGED', ERROR_MESSAGES.SESSION_CHANGED);
      if (!live.running || !live.managed || live.port !== config.listen.port) throw error('PROXY_OFFLINE', ERROR_MESSAGES.PROXY_OFFLINE);
      if (live.mode === 'tun' && live.tunReady === false) throw error('TUN_NOT_READY', ERROR_MESSAGES.TUN_NOT_READY);
    } catch (cause) {
      if (signal.aborted) throw signal.reason?.code ? signal.reason : error('CONNECTION_CANCELED', ERROR_MESSAGES.CONNECTION_CANCELED);
      const sameSession = networkReadGeneration === networkGeneration && (revision === state.revision || ['PROXY_CONFIG_CHANGED', 'PROXY_OFFLINE', 'PROXY_STOPPED', 'TUN_NOT_READY'].includes(cause.code)
        && session === JSON.stringify([state.proxy.sessionId, state.sessionConfigHash, state.proxy.port, state.proxy.mode]));
      if (!sameSession || cause.code === 'SESSION_CHANGED') throw error('SESSION_CHANGED', ERROR_MESSAGES.SESSION_CHANGED);
      const observationFailed = OBSERVATION_FAILURES.has(cause.code) && state.proxy.running && state.proxy.managed && !state.proxy.requestedStop;
      if (!observationFailed) { state.proxy.exit = null; state.proxy.systemExit = null; }
      diagnostic({ code: cause.code, operation: background ? 'health-verification' : 'verifying-exit', diagnostic: cause.diagnostic });
      if (revision === state.revision) {
        state.plans.clear(); rememberFailure(cause);
        if (observationFailed) healthState = { state: 'degraded', checkedAt: timestamp(), errorCode: state.lastError.code };
      }
      const systemPathFailed = cause.code?.startsWith('SYSTEM_') || cause.code === 'TUN_NOT_READY';
      const compatibilityPathFailed = isCompatibilityMode(config?.connectionMode || state.configuration.connectionMode);
      const supersededNetworkRead = networkReadGeneration !== networkGeneration;
      if (!observationFailed && !background && !['NETWORK_RECHECK_REQUIRED', 'SESSION_CHANGED'].includes(cause.code) && !supersededNetworkRead && !closing && !state.proxy.requestedStop && (state.browser.running || applicationGateway.status().running || (systemPathFailed || compatibilityPathFailed) && state.proxy.running && state.proxy.managed)) await blockFailedSession(cause);
      throw cause;
    }
    const observedAt = timestamp();
    if (!state.proxy.requestedStop) {
      state.proxy.exit = { ip: result.exitIp, observedAt, checkedAt: now(), revision, configHash: fingerprint, port: config.listen.port, binding: exitBinding(fingerprint), elapsedMs: result.elapsedMs };
      if (systemResult) {
        state.proxy.systemExit = { ip: systemResult.exitIp, observedAt, checkedAt: now(), revision, configHash: fingerprint, binding: exitBinding(fingerprint) };
        diagnostic({ code: 'SYSTEM_NETWORK_VERIFIED', operation: 'verifying-system-network' });
      }
      state.lastError = null; state.phase = 'ready';
      healthState = { state: 'idle', checkedAt: observedAt, errorCode: null };
      lastHealthCheck = now();
    }
    return { id: 'exit-ip', label: '指定 ISP 出口', status: mock ? 'mocked' : 'verified', exitIp: result.exitIp, elapsedMs: result.elapsedMs, observedAt, scope: mock ? '离线模拟，无实际网络验证' : '本次 HTTPS 请求命中配置中的预期出口 IP' };
  }

  function confirmed(body) { if (body.confirm !== true) throw error('CONFIRMATION_REQUIRED', ERROR_MESSAGES.CONFIRMATION_REQUIRED, 400); }
  function storePlan(type, payload) {
    for (const [key, value] of state.plans) if (value.expires <= now()) state.plans.delete(key);
    if (state.plans.size >= MAX_PLANS) state.plans.delete(state.plans.keys().next().value);
    const token = randomBytes(24).toString('base64url');
    const expires = now() + PLAN_TTL;
    state.plans.set(token, { type, payload, expires, revision: state.revision, fingerprint: state.configHash });
    return { token, expiresAt: new Date(expires).toISOString() };
  }
  function consumePlan(type, token) {
    const stored = typeof token === 'string' && state.plans.get(token);
    if (!stored || stored.type !== type || stored.expires <= now() || stored.revision !== state.revision) throw error('CONFIRMATION_INVALID', ERROR_MESSAGES.CONFIRMATION_INVALID, 400);
    state.plans.delete(token);
    return stored;
  }

  async function startProxy(body, requestedRevision, signal) {
    checkCanceled(signal);
    licensing.assertAllowed();
    if (body.routingMode !== undefined && (!['safe-rules', 'global'].includes(body.routingMode) || body.mode === 'http')) throw error('INPUT_INVALID', '路由模式必须是受支持的 TUN 策略', 400);
    if (body.externalReport !== undefined && typeof body.externalReport !== 'boolean') throw error('INPUT_INVALID', '外部报告选项必须为布尔值', 400);
    assertStartupRecovered();
    confirmed(body);
    await refreshLocal();
    checkCanceled(signal);
    const { config, fingerprint } = await loadConfiguration();
    const transport = validateTransportMode(body.mode || (isCompatibilityMode(config.connectionMode) ? 'http' : 'tun'));
    if (body.routingMode !== undefined && transport !== 'tun') throw error('INPUT_INVALID', '显式 HTTP 模式不接受 TUN 路由策略', 400);
    if (config.connectionMode === 'vpn-import' && transport === 'tun') await runtime.assertGlobalReady?.();
    checkCanceled(signal);
    if (requestedRevision !== state.revision || closing) throw error('SESSION_CHANGED', ERROR_MESSAGES.SESSION_CHANGED);
    if (body.port !== undefined && body.port !== config.listen.port) throw error('PROXY_PORT_INVALID', ERROR_MESSAGES.PROXY_PORT_INVALID, 400);
    if (!config.probe.expectedExitIps.length) throw error('EXPECTED_EXIT_REQUIRED', ERROR_MESSAGES.EXPECTED_EXIT_REQUIRED);
    if (state.browser.running) throw error('BROWSER_ALREADY_RUNNING', ERROR_MESSAGES.BROWSER_ALREADY_RUNNING);
    if (blockPending) throw error('PROCESS_STOP_TIMEOUT', ERROR_MESSAGES.PROCESS_STOP_TIMEOUT);
    // An armed physical firewall allows only the core to reach the relay. Its
    // reconnect path must not attempt Node HTTPS or DNS outside the tunnel.
    await cancelableRead(assertRelayConfiguration(config, undefined, { remote: !networkLockState.locked, signal }), signal);
    checkCanceled(signal);
    if (requestedRevision !== state.revision || closing) throw error('SESSION_CHANGED', ERROR_MESSAGES.SESSION_CHANGED);
    invalidate(); state.proxy.requestedStop = false; state.phase = 'starting'; state.lastError = null;
    sessionAbort = new AbortController(); licenseSuspended = null;
    const revision = state.revision;
    try {
      let vpnProxy, vpnNode;
      if (config.connectionMode === 'vpn-compat') {
        if (body.vpnConfirmed !== true) throw error('VPN_CONFIRMATION_REQUIRED', ERROR_MESSAGES.VPN_CONFIRMATION_REQUIRED);
        if (body.mode !== undefined && body.mode !== 'http') throw error('VPN_COMPAT_HTTP_ONLY', ERROR_MESSAGES.VPN_COMPAT_HTTP_ONLY);
        await assertSetupIdle();
        await runtime.assertCompatibilityReady?.();
        const input = { config, secrets: mock ? {} : await readSavedSecrets(config), signal };
        vpnProxy = (await verifyCompatibility(input, revision, body.vpnProxy)).vpnProxy;
      } else if (config.connectionMode === 'vpn-import') {
        if (body.vpnProxy !== undefined) throw error('VPN_PROXY_INVALID', ERROR_MESSAGES.VPN_PROXY_INVALID);
        if (transport === 'tun' && networkLockState.locked) {
          const profile = await vpnConfigStore.status();
          const candidates = await vpnConfigStore.candidates();
          if (!runtime.resumeImportedNode) throw error('NETWORK_LOCK_RECOVERY_REQUIRED', ERROR_MESSAGES.NETWORK_LOCK_RECOVERY_REQUIRED);
          vpnNode = await runtime.resumeImportedNode({ config, nodes: candidates });
          const latestProfile = await vpnConfigStore.status();
          const latestCandidates = await vpnConfigStore.candidates();
          if (latestProfile.id !== profile.id || !latestCandidates.some(candidate => hash(candidate.outbound) === hash(vpnNode))) throw error('VPN_IMPORT_CONFLICT', ERROR_MESSAGES.VPN_IMPORT_CONFLICT);
          assertRevision(revision);
        } else vpnNode = (await verifyImportedConfiguration({ config, secrets: mock ? {} : await readSavedSecrets(config), signal }, revision, { firstVerified: true })).vpnNode;
      } else if (body.vpnProxy !== undefined) throw error('VPN_PROXY_INVALID', ERROR_MESSAGES.VPN_PROXY_INVALID);
      networkLifecycle = { state: 'stable', reason: null };
      const applicationPaths = transport === 'tun' && !mock ? await options.getApplicationPaths?.() || [] : [];
      assertRevision(revision);
      licensing.assertAllowed();
      const running = await runtime.start({ config, mode: transport, signal, ...(transport === 'tun' ? { routingMode: body.routingMode || 'safe-rules', applicationPaths } : {}), ...(vpnProxy ? { vpnProxy } : {}), ...(vpnNode ? { vpnNode } : {}) });
      assertRevision(revision);
      state.proxy.running = running.running; state.proxy.managed = running.managed; state.proxy.port = config.listen.port;
      state.proxy.mode = running.mode || transport; state.proxy.sessionId = running.sessionId || null; state.proxy.vpnNodeHash = running.vpnNodeHash || null;
      state.proxy.trafficBlocked = running.trafficBlocked === true; state.proxy.trafficHoldStatus = running.trafficBlocked ? running.trafficBlockConfirmed === true ? 'blocked' : 'failed' : null;
      licensing.assertAllowed();
      state.proxy.routingMode = running.routingMode || (transport === 'tun' ? body.routingMode || 'safe-rules' : null);
      state.sessionConfigHash = fingerprint;
      state.operation = { stage: 'verifying-exit', message: body.externalReport === true ? '正在核验 ISP 出口并生成所选多站报告…' : '正在核验 ISP 出口…', at: timestamp() };
      if (body.externalReport === true) await runProbes({ multi: true, thirdParty: true });
      else await verifyExit();
      assertRevision(revision);
      licensing.assertAllowed();
      licensing.refreshIfDue?.();
      if (body.optimize === true) {
        state.operation = { stage: 'optimizing-environment', message: '正在根据出口国家与城市调整环境…', at: timestamp() };
        try {
          const geo = environment.status().preferences?.work?.mode === 'custom' ? null : await environmentGeography();
          environmentState = await environment.optimize({ geo, localize: true, force: true });
          reportPartialEnvironment(environmentState);
        } catch (cause) {
          if (['SESSION_CHANGED', 'PROXY_CONFIG_CHANGED', 'PROXY_OFFLINE', 'PROXY_STOPPED', 'TUN_NOT_READY'].includes(cause.code)) throw cause;
          await recordEnvironmentFailure(cause, cause.code === 'GEO_UNVERIFIED' ? 'exit-location' : undefined);
        }
        assertRevision(revision);
      }
      licensing.assertAllowed();
      await resumeApplicationGateway();
      assertRevision(revision);
      licensing.assertAllowed();
      return publicStatus();
    } catch (cause) {
      if (signal?.aborted && !['PROCESS_STOP_TIMEOUT', 'SETUP_PROXY_STOP_FAILED'].includes(cause.code)) cause = signal.reason?.code ? signal.reason : error('CONNECTION_CANCELED', ERROR_MESSAGES.CONNECTION_CANCELED);
      state.proxy.exit = null;
      const permission = licensing.status();
      if (permission.mode === 'required' && !permission.allowed && state.proxy.mode === 'tun' && state.proxy.managed && state.proxy.running) {
        licenseSuspended ||= error(permission.reason || 'LICENSE_REQUIRED', permission.message || ERROR_MESSAGES.LICENSE_REQUIRED);
      }
      if (licenseSuspended && state.proxy.mode === 'tun' && state.proxy.managed && state.proxy.running) { await suspendPaidSession(licenseSuspended); throw cause; }
      let cleanupError;
      try { if ((await runtime.status()).managed) await runtime.stop(); }
      catch (failure) { cleanupError = failure; }
      const final = await runtime.status().catch(() => null);
      state.proxy.running = final ? final.running : true;
      state.proxy.managed = final ? final.managed : true;
      state.proxy.requestedStop = true;
      blockPending = Boolean(cleanupError);
      if (cleanupError) { rememberFailure(cleanupError); throw cleanupError; }
      if (cause.code === 'CONNECTION_CANCELED') { state.phase = 'stopping'; state.lastError = null; }
      else rememberFailure(cause);
      throw cause;
    } finally { state.operation = null; }
  }

  async function endSession() {
    state.phase = 'stopping';
    try {
      await applicationGateway.stop();
      await browsers.close();
      state.browser = await browsers.status();
      if (state.browser.running) throw error('BROWSER_CLOSE_TIMEOUT', ERROR_MESSAGES.BROWSER_CLOSE_TIMEOUT);
      await runtime.stop();
      state.proxy.trafficBlocked = false; state.proxy.trafficHoldStatus = null; licenseSuspended = null;
      state.proxy.running = false; state.proxy.managed = false; state.sessionConfigHash = null;
      await setupVerifier.recoverAndStop?.();
      blockPending = false;
      await refreshNetworkLock({ cached: true });
      state.proxy.running = false; state.proxy.managed = false; state.sessionConfigHash = null;
      state.phase = 'idle'; state.lastError = null;
      return { ...publicStatus(), ended: true, note: '已先关闭独立浏览器，再停止受管代理；浏览器资料与环境设置保留。断网锁需另行明确解除。' };
    } catch (cause) { rememberFailure(cause); throw cause; }
  }

  async function suspendPaidSession(cause) {
    if (state.proxy.mode !== 'tun' || !state.proxy.running || !state.proxy.managed) return endSession();
    state.proxy.requestedStop = true; state.proxy.trafficHoldStatus = 'pending';
    networkLifecycle = { state: 'blocked', reason: 'license' };
    try {
      if (!runtime.holdTraffic) throw error('CORE_TRAFFIC_GATE_FAILED', ERROR_MESSAGES.CORE_TRAFFIC_GATE_FAILED);
      const held = await runtime.holdTraffic({ reason: cause.code });
      if (!(held?.trafficBlocked === true && held?.trafficBlockConfirmed === true || held?.blocked === true && held?.confirmed === true)) throw error('CORE_TRAFFIC_GATE_FAILED', ERROR_MESSAGES.CORE_TRAFFIC_GATE_FAILED);
      state.proxy.trafficBlocked = true; state.proxy.trafficHoldStatus = 'blocked';
      rememberFailure(cause); state.phase = 'traffic-blocked'; blockPending = false;
    } catch (failure) {
      state.proxy.trafficHoldStatus = 'failed'; rememberFailure(failure);
      // An unconfirmed API switch must never be "repaired" by removing TUN.
      // The expiry timer retries; explicit disconnect remains available.
    }
  }

  async function resumePaidSession(signal) {
    checkCanceled(signal); licensing.assertAllowed(); assertStartupRecovered();
    await refreshLocal({ force: true });
    if (!state.proxy.running || !state.proxy.managed || state.proxy.mode !== 'tun' || !state.proxy.trafficBlocked || !runtime.resumeTraffic) throw error('CORE_TRAFFIC_GATE_FAILED', ERROR_MESSAGES.CORE_TRAFFIC_GATE_FAILED);
    const { fingerprint } = await loadConfiguration();
    if (fingerprint !== state.sessionConfigHash) throw error('PROXY_CONFIG_CHANGED', ERROR_MESSAGES.PROXY_CONFIG_CHANGED);
    checkCanceled(signal); licensing.assertAllowed();
    invalidate(); const revision = state.revision;
    sessionAbort = new AbortController(); licenseSuspended = null;
    state.proxy.requestedStop = false; networkLifecycle = { state: 'stable', reason: 'license-resume' };
    state.operation = { stage: 'resuming-licensed-session', message: '正在恢复代理转发并重新核验 ISP 出口…', at: timestamp() };
    try {
      await runtime.resumeTraffic(); checkCanceled(signal); licensing.assertAllowed(); assertRevision(revision);
      state.proxy.trafficBlocked = false; state.proxy.trafficHoldStatus = null;
      await verifyExit({ force: true }); checkCanceled(signal); licensing.assertAllowed(); assertRevision(revision);
      await resumeApplicationGateway();
      checkCanceled(signal); licensing.assertAllowed(); assertRevision(revision);
      return publicStatus();
    } catch (cause) {
      invalidate(); await suspendPaidSession(licenseSuspended || cause); throw cause;
    } finally { state.operation = null; }
  }

  async function workspaceConfiguration({ required = true } = {}) {
    assertStartupRecovered();
    let config;
    try { config = await readSessionConfiguration(); }
    catch (cause) { if (required) throw cause; return { configured: false, pinned: false, binding: null }; }
    const pinned = Array.isArray(config.probe?.expectedExitIps) && config.probe.expectedExitIps.length > 0;
    if (required && !pinned) throw error('EXPECTED_EXIT_REQUIRED', ERROR_MESSAGES.EXPECTED_EXIT_REQUIRED);
    // Bind the ISP destination and independently verified exits, not an upstream
    // VPN node, password, local port, licence or per-connection revision.
    const binding = pinned ? hash([config.upstream.type, config.upstream.host.toLowerCase(), config.upstream.port, [...new Set(config.probe.expectedExitIps.map(ip => ip.toLowerCase()))].sort()]) : null;
    return { configured: true, pinned, binding, config };
  }

  async function workspaceStatus() {
    const configuration = await workspaceConfiguration({ required: false }), saved = await workspaces.list();
    const browser = await browsers.status(); state.browser = browser;
    const observation = browserObservation.snapshot().report;
    const preferences = (await onboarding.status()).preferences || {};
    const defaultIdentity = await defaultWorkspaceIdentity();
    return { version: 1, configured: configuration.configured, pinned: configuration.pinned, limits: { active: 24, total: 96 },
      defaultIdentity, defaultBrowser: preferences.browser || 'chrome',
      activeId: browser.running ? browser.workspaceId || null : null, services: [...BROWSER_WORKSPACE_SERVICES],
      items: saved.items.map(({ binding, identity, ...item }) => ({ ...item, browser: workspaceBrowser(item), ...(workspaceBrowser(item) === 'fingerprint' ? { identity: identity || defaultIdentity, identityInherited: !identity } : {}), bindingMatches: binding === configuration.binding,
        ...(observation?.source?.workspaceId === item.id ? { lastObservation: { observedAt: observation.observedAt, status: observation.summary.status,
          workspaceId: item.id, identityRevision: observation.source.identityRevision } } : {}) })) };
  }

  async function defaultWorkspaceIdentity() {
    const preferences = (await onboarding.status()).preferences || {};
    return { version: 1, language: preferences.fingerprintLanguage || 'auto', timezone: preferences.fingerprintTimezone || 'auto', nativeGraphics: preferences.fingerprintNativeGraphics === true };
  }

  async function workspaceIdentity(id) {
    if (workspaceBrowser(await workspaces.get(id)) !== 'fingerprint') throw error('BROWSER_WORKSPACE_INVALID', '普通浏览器工作区不使用指纹身份设置', 400);
    return (await workspaces.ensureIdentity(id, await defaultWorkspaceIdentity())).identity;
  }

  async function changeWorkspace(action, body) {
    const allowed = action === 'create' ? ['confirm', 'name', 'services', 'browser', 'identity'] : action === 'update' ? ['confirm', 'id', 'name', 'services', 'identity', 'rebind'] : action === 'replace' ? ['confirm', 'id', 'name'] : ['confirm', 'id'];
    if (Object.keys(body).some(key => !allowed.includes(key)) || body.rebind !== undefined && body.rebind !== true) throw error('INPUT_INVALID', '工作区设置包含未知选项', 400);
    confirmed(body); assertStartupRecovered();
    if (action !== 'create') {
      await workspaces.get(body.id);
      const browser = await browsers.status(); state.browser = browser;
      if (browser.running && browser.workspaceId === body.id) throw error('WORKSPACE_ACTIVE', '请先正常结束此工作区，再修改或移除卡片');
    }
    if (action === 'remove') await workspaces.remove(body.id);
    else if (action === 'archive') await workspaces.archive(body.id);
    else if (action === 'restore') await workspaces.restore(body.id);
    else if (action === 'replace') {
      if (workspaceBrowser(await workspaces.get(body.id)) === 'fingerprint') await workspaceIdentity(body.id);
      const result = await workspaces.replace(body.id, body.name === undefined ? {} : { name: body.name });
      invalidateBrowserPlans(); browserObservation.invalidate();
      return { ...await workspaceStatus(), workspace: result.item, previous: result.previous };
    }
    else {
      const selected = { ...(body.name !== undefined ? { name: body.name } : {}), ...(body.services !== undefined ? { services: body.services } : {}) };
      const browser = action === 'create' ? body.browser !== undefined ? body.browser : (await onboarding.status()).preferences?.browser || 'chrome' : workspaceBrowser(await workspaces.get(body.id));
      if (action === 'create') selected.browser = browser;
      if (body.identity !== undefined && browser !== 'fingerprint') throw error('BROWSER_WORKSPACE_INVALID', '普通浏览器工作区不使用指纹身份设置', 400);
      if (body.identity !== undefined) selected.identity = body.identity;
      else if (action === 'create' && browser === 'fingerprint') selected.identity = await defaultWorkspaceIdentity();
      if (action === 'create' || body.rebind === true) selected.binding = (await workspaceConfiguration()).binding;
      if (action === 'create') await workspaces.create(selected); else await workspaces.update(body.id, selected);
    }
    invalidateBrowserPlans(); browserObservation.invalidate();
    return workspaceStatus();
  }

  async function startWorkspace(body, requestedRevision, signal) {
    if (Object.keys(body).some(key => !['confirm', 'id', 'confirmSwitch', 'vpnConfirmed', 'vpnProxy'].includes(key)) || body.confirmSwitch !== undefined && typeof body.confirmSwitch !== 'boolean') throw error('INPUT_INVALID', '开始工作请求包含未知选项', 400);
    confirmed(body); checkCanceled(signal); licensing.assertAllowed(); assertStartupRecovered();
    const configuration = await workspaceConfiguration();
    const workspace = await workspaces.assertBinding(body.id, configuration.binding);
    const browser = workspaceBrowser(workspace);
    await refreshLocal(); checkCanceled(signal);
    if (requestedRevision !== state.revision) throw error('SESSION_CHANGED', ERROR_MESSAGES.SESSION_CHANGED);
    if (state.browser.running) {
      if (state.browser.workspaceId === workspace.id && state.browser.browser === browser && state.browser.managed && state.proxy.running && state.proxy.managed && !state.proxy.requestedStop) {
        await verifyExit({ force: true }); checkCanceled(signal); licensing.assertAllowed();
        await workspaces.assertBinding(body.id, (await workspaceConfiguration()).binding);
        await workspaces.touch(body.id);
        return { workspaceId: workspace.id, reused: true, browser: state.browser, status: publicStatus() };
      }
      if (body.confirmSwitch !== true) throw error('WORKSPACE_SWITCH_CONFIRM_REQUIRED', '已有浏览器工作中，请确认先正常结束当前窗口再切换工作区');
      await browsers.close(); state.browser = await browsers.status(); checkCanceled(signal);
      if (state.browser.running) throw error('BROWSER_CLOSE_TIMEOUT', ERROR_MESSAGES.BROWSER_CLOSE_TIMEOUT);
      invalidateBrowserPlans(); browserObservation.invalidate();
    }
    checkCanceled(signal);
    if (!state.proxy.running) {
      const preferences = (await onboarding.status()).preferences || {};
      const compatibility = configuration.config.connectionMode === 'vpn-compat', imported = configuration.config.connectionMode === 'vpn-import';
      const takeover = imported ? preferences.takeoverMode || 'global' : preferences.relayRoutingMode || 'global';
      const mode = compatibility || imported && takeover === 'application' ? 'http' : 'tun';
      await startProxy({ confirm: true, mode, ...(mode === 'tun' ? { routingMode: takeover === 'global' ? 'global' : 'safe-rules' } : {}),
        optimize: preferences.autoOptimize === true, externalReport: preferences.externalReport === true,
        ...(compatibility ? { vpnConfirmed: body.vpnConfirmed, ...(body.vpnProxy !== undefined ? { vpnProxy: body.vpnProxy } : {}) } : {}) }, requestedRevision, signal);
    }
    checkCanceled(signal); licensing.assertAllowed();
    await workspaces.assertBinding(body.id, (await workspaceConfiguration()).binding);
    const planned = await browserPlan({ browser, workspaceId: workspace.id, services: workspace.services, fresh: false });
    checkCanceled(signal);
    const result = await launchBrowser({ confirm: true, token: planned.token });
    checkCanceled(signal); await workspaces.touch(body.id);
    return { workspaceId: workspace.id, result, browser: state.browser, status: publicStatus() };
  }

  async function browserPlan(body) {
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw error('INPUT_INVALID', '浏览器启动请求无效', 400);
    licensing.assertAllowed();
    assertStartupRecovered();
    await verifyExit();
    const revision = state.revision;
    const preferences = (await onboarding.status()).preferences || {};
    let workspace;
    if (body.workspaceId !== undefined) {
      workspace = await workspaces.assertBinding(body.workspaceId, (await workspaceConfiguration()).binding);
      if (body.browser !== undefined && body.browser !== workspaceBrowser(workspace) || body.fresh === true) throw error('BROWSER_WORKSPACE_INVALID', '工作区需要使用已固定的浏览器与保留资料', 400);
    }
    const browser = body.browser || (workspace ? workspaceBrowser(workspace) : preferences.browser || 'chrome');
    const fresh = body.workspaceId ? false : body.fresh === undefined ? browser === 'fingerprint' ? preferences.fingerprintFresh === true : preferences.fresh === true : body.fresh === true;
    const settings = browser === 'fingerprint' ? await fingerprintSettings({ refresh: true, retryFailed: true, ...(body.workspaceId ? { identity: await workspaceIdentity(body.workspaceId) } : {}) }) : null;
    const observationEndpoint = browser === 'fingerprint' || workspace ? await browserObservation.endpoint?.() : null;
    const plan = await browsers.plan({ browser, service: body.service || 'exit', language: body.language || settings?.resolvedLanguage || environmentState.appliedRegion?.locale || (environmentState.status === 'optimized' ? environmentState.current?.culture : null) || 'en-US', port: state.proxy.port, fresh,
      ...(body.workspaceId ? { workspaceId: body.workspaceId, ...(body.services !== undefined ? { services: body.services } : {}) } : {}),
      ...(settings ? { timezone: settings.resolvedTimezone, nativeGraphics: settings.nativeGraphics } : {}), ...(observationEndpoint ? { observationPort: observationEndpoint.port } : {}) });
    assertRevision(revision);
    if ((await browsers.status()).running) throw error('BROWSER_ALREADY_RUNNING', ERROR_MESSAGES.BROWSER_ALREADY_RUNNING);
    assertRevision(revision);
    const token = storePlan('browser', plan);
    if (settings) state.plans.get(token.token).browserRegion = { exitIp: state.proxy.exit.ip,
      languageAuto: !body.language && settings.language === 'auto', timezoneAuto: settings.timezone === 'auto' };
    const profile = plan.workspaceId ? `backend/runtime/browser-profiles/workspaces/${plan.workspaceId}/${plan.browserId}` : plan.fresh ? `backend/runtime/browser-profiles/fresh/${plan.browserId}/${plan.freshId}` : `backend/runtime/browser-profiles/${plan.browserId}`;
    return { ...token, mode: 'plan-only', browser: plan.label, browserId: plan.browserId, service: plan.service, fresh: !!plan.fresh, profile, args: plan.args.map(arg => arg.startsWith('--user-data-dir=') ? `--user-data-dir=${profile}` : arg), url: plan.url, language: plan.language, ...(plan.workspaceId ? { workspaceId: plan.workspaceId, services: plan.services, urls: plan.urls } : {}), ...(plan.fingerprint ? { fingerprint: plan.fingerprint } : {}), network: { proxy: `127.0.0.1:${plan.port}`, webrtcPolicy: plan.webrtcPolicy, webrtcVerification: 'unverified', browserExitVerification: 'unverified' }, exit: publicStatus().proxy.exit };
  }

  function currentBrowserGeography() {
    if (mock || !freshObservation(state.proxy.exit, state.configHash)) return null;
    const saved = browserGeography && browserGeography.binding === exitBinding(state.configHash)
      && now() >= browserGeography.checkedAt && now() - browserGeography.checkedAt <= EXIT_TTL
      && equalIp(browserGeography.ip, state.proxy.exit.ip) ? browserGeography : null;
    if (saved?.geo) return saved;
    const generatedAt = Date.parse(latestReport?.generatedAt);
    if (reportRevision === state.revision && now() >= generatedAt && now() - generatedAt <= EXIT_TTL
      && latestReport?.summary?.consistent && latestReport?.geo?.verified === true
      && verifiedExitGeography(latestReport.geo, state.proxy.exit.ip, [state.proxy.exit.ip])) return { geo: latestReport.geo, checkedAt: generatedAt };
    return saved;
  }
  async function fingerprintSettings({ refresh = false, retryFailed = false, identity } = {}) {
    const preferences = (await onboarding.status()).preferences || {};
    const language = identity?.language || preferences.fingerprintLanguage || 'auto', timezone = identity?.timezone || preferences.fingerprintTimezone || 'auto';
    let current = currentBrowserGeography();
    if (refresh && !mock && (language === 'auto' || timezone === 'auto') && (!current || retryFailed && current.code)) {
      try { await environmentGeography(); }
      catch (cause) {
        // An unavailable geography service may fall back to local settings. A
        // stopped/replaced/expired proxy session must still abort the launch.
        if (cause.code !== 'GEO_UNVERIFIED') throw cause;
        browserGeography = { ip: state.proxy.exit.ip, binding: exitBinding(state.configHash), checkedAt: now(), code: 'GEO_UNVERIFIED' };
      }
      current = currentBrowserGeography();
    }
    const geo = current?.geo;
    // English is a browser-only default for Singapore; keep the existing
    // Windows multilingual/input-method policy unchanged.
    const regionalLanguage = geo ? localeForGeo(geo) || (geo.countryCode === 'SG' ? 'en-SG' : null) : null;
    const regionalTimezone = geo?.timezone;
    const languageSource = language !== 'auto' ? 'manual' : regionalLanguage ? 'verified-exit' : 'local-environment';
    const timezoneSource = timezone !== 'auto' ? 'manual' : regionalTimezone ? 'verified-exit' : 'local-environment';
    return { language, timezone, nativeGraphics: identity ? identity.nativeGraphics : preferences.fingerprintNativeGraphics === true,
      alignmentSource: geo ? 'verified-exit' : 'local-environment', languageSource, timezoneSource,
      ...(geo ? { alignmentRevision: state.revision, alignmentExitIp: state.proxy.exit.ip, alignmentExpiresAt: new Date(current.checkedAt + EXIT_TTL).toISOString() } : {}),
      ...(current?.code && (language === 'auto' || timezone === 'auto') ? { alignmentCode: current.code } : {}),
      resolvedLanguage: language === 'auto' ? regionalLanguage || environmentState.current?.culture || Intl.DateTimeFormat().resolvedOptions().locale || 'en-US' : language,
      resolvedTimezone: timezone === 'auto' ? regionalTimezone || Intl.DateTimeFormat().resolvedOptions().timeZone : timezone };
  }
  async function fingerprintStatus() {
    return { settings: await fingerprintSettings(), runtime: await browsers.fingerprintStatus?.() || { state: 'unavailable', verified: false }, install: { ...fingerprintInstall }, security: fingerprintSecurity.snapshot() };
  }
  async function installFingerprint(body) {
    if (Object.keys(body).some(key => key !== 'confirm')) throw error('INPUT_INVALID', '引擎准备不接受额外选项', 400);
    confirmed(body);
    if (closing || repairPending) throw error('SERVICE_STOPPING', ERROR_MESSAGES.SERVICE_STOPPING, 503);
    if (fingerprintInstallWork) return { install: { ...fingerprintInstall } };
    fingerprintInstallAbort = new AbortController();
    fingerprintInstall = { status: options.fingerprintBundleRoot ? 'copying-bundle' : 'verifying', receivedBytes: 0, startedAt: timestamp() };
    const prepare = options.installFingerprintBrowser || (({ target, ...settings }) => options.fingerprintBundleRoot
      ? prepareFingerprintBrowserFromBundle(options.fingerprintBundleRoot, target, settings)
      : prepareFingerprintBrowser(target, settings));
    fingerprintInstallWork = Promise.resolve().then(() => prepare({ target: fingerprintRoot, signal: fingerprintInstallAbort.signal,
      onProgress: progress => {
        if (closing) return;
        const stage = progress?.status || progress?.stage;
        if (stage === 'downloading') fingerprintInstall.status = 'downloading';
        else if (stage === 'copying-bundle') fingerprintInstall.status = 'copying-bundle';
        else if (stage === 'extracting') fingerprintInstall.status = 'extracting';
        else if (['checking', 'verifying', 'verifying-archive', 'verifying-engine'].includes(stage)) fingerprintInstall.status = 'verifying';
        for (const key of ['receivedBytes', 'totalBytes']) if (Number.isSafeInteger(progress?.[key]) && progress[key] >= 0 && progress[key] <= 2 * 1024 * 1024 * 1024) fingerprintInstall[key] = progress[key];
      },
    })).then(async () => {
      browserOptions = await browsers.rescan?.() || await browsers.listBrowsers();
      fingerprintInstall = { ...fingerprintInstall, status: 'installed', completedAt: timestamp() };
      diagnostic({ code: 'FINGERPRINT_ENGINE_INSTALLED', operation: 'preparing-browser-engine' });
    }).catch(cause => {
      fingerprintInstall = { status: 'failed', failedStage: fingerprintInstall.status, code: /^[A-Z][A-Z0-9_]{0,79}$/.test(cause?.code || '') ? cause.code : 'FINGERPRINT_ENGINE_INSTALL_FAILED', completedAt: timestamp() };
      diagnostic({ code: 'FINGERPRINT_ENGINE_INSTALL_FAILED', operation: 'preparing-browser-engine' });
    }).finally(() => { fingerprintInstallWork = null; fingerprintInstallAbort = null; });
    return { install: { ...fingerprintInstall } };
  }
  async function startBrowserObservation(body = {}) {
    if (Object.keys(body).some(key => !['confirm', 'browser', 'launch', 'workspaceId'].includes(key)) || body.launch !== undefined && typeof body.launch !== 'boolean'
      || body.browser !== undefined && !['chrome', 'edge', 'fingerprint'].includes(body.browser)) throw error('INPUT_INVALID', '浏览器检测请求包含未知选项', 400);
    confirmed(body); assertStartupRecovered();
    await applicationProxyLease();
    const revision = state.revision, { config, fingerprint } = await assertActive();
    const preferences = (await onboarding.status()).preferences || {};
    const current = await browsers.status(); state.browser = current;
    const workspaceId = body.workspaceId === undefined ? current.running ? current.workspaceId : undefined : body.workspaceId;
    let workspace;
    if (workspaceId !== undefined) {
      workspace = await workspaces.assertBinding(workspaceId, (await workspaceConfiguration()).binding);
      if (body.browser !== undefined && body.browser !== workspaceBrowser(workspace)) throw error('BROWSER_WORKSPACE_INVALID', '请使用此工作区固定的浏览器进行检测', 400);
    }
    const browser = body.browser || (workspace ? workspaceBrowser(workspace) : preferences.browser || 'chrome');
    if (workspace && (current.running && (current.workspaceId !== workspaceId || current.browser !== browser || !current.managed) || body.launch === false && !current.running)) throw error('WORKSPACE_OBSERVATION_TARGET_REQUIRED', '请先打开这个用户环境，再生成它的检测链接', 409);
    if (body.launch !== false && current.running && (current.browser !== browser || !current.managed || browser !== 'fingerprint' && !workspace)) throw error('BROWSER_ALREADY_RUNNING', ERROR_MESSAGES.BROWSER_ALREADY_RUNNING);
    const settings = browser === 'fingerprint' ? await fingerprintSettings({ refresh: !current.running, retryFailed: true,
      ...(workspaceId ? { identity: await workspaceIdentity(workspaceId) } : {}) }) : null;
    const language = current.running && current.browser === browser ? current.language || settings?.resolvedLanguage || environmentState.appliedRegion?.locale || 'en-US' : browser === 'fingerprint' ? settings.resolvedLanguage : environmentState.appliedRegion?.locale || 'en-US';
    const timezone = current.running && current.browser === browser ? current.fingerprint?.timezone || settings?.resolvedTimezone || Intl.DateTimeFormat().resolvedOptions().timeZone : browser === 'fingerprint' ? settings.resolvedTimezone : Intl.DateTimeFormat().resolvedOptions().timeZone;
    const target = current.running && current.browser === browser ? observationTarget(current) : { workspaceId: workspaceId || null, identityRevision: null, expectedIdentity: null };
    await browserObservation.updateTarget?.(target);
    const session = await browserObservation.createSession({ binding: { revision, configHash: fingerprint, exitBinding: hash(exitBinding(fingerprint)) },
      expectedExitIps: config.probe.expectedExitIps.length ? config.probe.expectedExitIps : [state.proxy.exit.ip], browser,
      language, timezone, ...target,
    });
    assertRevision(revision);
    let launched = null;
    if (body.launch !== false) {
      try {
        licensing.assertAllowed();
        if (current.running) {
          launched = await browsers.openObservation({ observationUrl: session.url, ...(workspaceId ? { workspaceId } : {}), port: state.proxy.port });
        } else {
          const plan = await browsers.plan({ browser, service: 'observation', observationUrl: session.url, port: state.proxy.port, language,
            ...(workspaceId ? { workspaceId, fresh: false } : { fresh: browser === 'fingerprint' ? preferences.fingerprintFresh === true : preferences.fresh === true }),
            ...(browser === 'fingerprint' ? { timezone, nativeGraphics: settings.nativeGraphics } : {}) });
          assertRevision(revision);
          launched = await browsers.launch(plan);
        }
        state.browser = await browsers.status(); assertRevision(revision); licensing.assertAllowed();
        const launchedTarget = observationTarget(state.browser);
        if (state.browser.running && state.browser.managed && state.browser.browser === browser && launchedTarget.identityRevision) await browserObservation.markManagedLaunch?.(launchedTarget);
      } catch (cause) { browserObservation.invalidate(); throw cause; }
    }
    return { observation: browserObservation.snapshot(), ...(launched ? { launched } : {}), url: session.url };
  }

  function observationTarget(browser) {
    const fp = browser?.fingerprint;
    const expectedIdentity = fp && fp.engineVersion !== 'mocked' ? { platform: fp.platform, platformVersion: fp.platformVersion, cores: fp.cores, engineVersion: fp.engineVersion, nativeGraphics: fp.nativeGraphics } : null;
    return { workspaceId: browser?.workspaceId || null,
      identityRevision: fp ? hash([browser.workspaceId || null, fp.seed, browser.language, fp.timezone, fp.nativeGraphics, fp.cores, fp.platformVersion, fp.engineVersion]) : null,
      expectedIdentity };
  }
  async function rotateFingerprint(body = {}) {
    if (Object.keys(body).some(key => !['confirm', 'workspaceId'].includes(key))) throw error('INPUT_INVALID', '指纹轮换不接受额外选项', 400);
    confirmed(body); licensing.assertAllowed(); assertStartupRecovered();
    if (!browsers.rotateFingerprint) throw error('FEATURE_UNAVAILABLE', '当前浏览器管理器不支持指纹轮换', 409);
    const previous = await browsers.status();
    if (body.workspaceId !== undefined) {
      const workspace = await workspaces.get(body.workspaceId);
      if (workspace.archivedAt) throw error('WORKSPACE_ARCHIVED', ERROR_MESSAGES.WORKSPACE_ARCHIVED, 409);
      if (workspaceBrowser(workspace) !== 'fingerprint') throw error('BROWSER_WORKSPACE_INVALID', '普通浏览器工作区不使用指纹轮换', 400);
    }
    if (previous.running && body.workspaceId !== undefined && previous.workspaceId !== body.workspaceId) throw error('WORKSPACE_ACTIVE', '另一个浏览器环境正在运行，请先结束它，再更换目标环境的指纹', 409);
    if (previous.running) await applicationProxyLease();
    const revision = state.revision;
    const result = await browsers.rotateFingerprint({ confirm: true, ...(body.workspaceId ? { workspaceId: body.workspaceId } : {}) });
    browserObservation.invalidate(); invalidateBrowserPlans(); state.browser = await browsers.status();
    assertRevision(revision, !previous.running);
    // A successful rotation changes only this stable profile's seed. New
    // launch plans still go through the verified route and paid-use boundary.
    if (previous.running && previous.browser === 'fingerprint') {
      const plan = await browserPlan({ browser: 'fingerprint', fresh: false, service: 'exit', ...(previous.workspaceId ? { workspaceId: previous.workspaceId } : {}) });
      await launchBrowser({ token: plan.token, confirm: true });
    }
    return { ...result, rotated: true, relaunched: previous.running && previous.browser === 'fingerprint', browser: state.browser };
  }

  async function closeBrowserForProfileChange(browser, workspaceId) {
    const current = await browsers.status(); state.browser = current;
    if (!current.running) return;
    if (current.browser !== browser || (current.workspaceId || undefined) !== workspaceId) throw error('BROWSER_PROFILE_SCOPE_MISMATCH', ERROR_MESSAGES.BROWSER_PROFILE_SCOPE_MISMATCH);
    if (current.fresh === true) throw error('BROWSER_PROFILE_FRESH_RUNNING', ERROR_MESSAGES.BROWSER_PROFILE_FRESH_RUNNING);
    if (!current.managed) throw error('BROWSER_SESSION_UNTRACKED', ERROR_MESSAGES.BROWSER_SESSION_UNTRACKED);
    try { await browsers.close(); }
    catch (cause) { try { state.browser = await browsers.status(); } catch {} throw cause; }
    state.browser = await browsers.status();
    if (state.browser.running) throw error('BROWSER_CLOSE_TIMEOUT', ERROR_MESSAGES.BROWSER_CLOSE_TIMEOUT);
  }

  async function browserProfiles(browser) {
    if (!['chrome', 'edge', 'fingerprint'].includes(browser)) throw error('INPUT_INVALID', '请选择要管理资料的浏览器', 400);
    assertStartupRecovered();
    if (!browsers.profileArchives) throw error('FEATURE_UNAVAILABLE', '当前浏览器管理器不支持资料归档', 409);
    return browsers.profileArchives({ browser });
  }

  async function changeBrowserProfile(action, body) {
    const fields = action === 'restore' ? ['confirm', 'browser', 'archiveId'] : ['confirm', 'browser'];
    if (Object.keys(body).some(key => !fields.includes(key)) || !['chrome', 'edge', 'fingerprint'].includes(body.browser)
      || action === 'restore' && !validBrowserWorkspaceId(body.archiveId)) throw error('INPUT_INVALID', '浏览器资料请求无效', 400);
    confirmed(body); assertStartupRecovered();
    const method = action === 'restore' ? browsers.restoreProfile : browsers.refreshProfile;
    if (!method) throw error('FEATURE_UNAVAILABLE', '当前浏览器管理器不支持资料归档', 409);
    // Even a failed move invalidates plans made against the previous contents
    // of the same canonical directory. Routing and licence state stay separate.
    invalidateBrowserPlans(); browserObservation.invalidate();
    await closeBrowserForProfileChange(body.browser);
    const result = await method({ browser: body.browser, confirm: true, ...(action === 'restore' ? { archiveId: body.archiveId } : {}) });
    try { await onboarding.preferences(body.browser === 'fingerprint' ? { fingerprintFresh: false } : { fresh: false }); }
    catch { throw error('BROWSER_PROFILE_PREFERENCES_FAILED', ERROR_MESSAGES.BROWSER_PROFILE_PREFERENCES_FAILED); }
    state.browser = await browsers.status();
    return result;
  }

  async function refreshWorkspaceProfile(body) {
    if (Object.keys(body).some(key => !['confirm', 'id'].includes(key)) || !validBrowserWorkspaceId(body.id)) throw error('INPUT_INVALID', '请选择要刷新资料的用户环境', 400);
    confirmed(body); assertStartupRecovered();
    const workspace = await workspaces.get(body.id);
    if (workspace.archivedAt) throw error('WORKSPACE_ARCHIVED', ERROR_MESSAGES.WORKSPACE_ARCHIVED);
    invalidateBrowserPlans(); browserObservation.invalidate();
    await closeBrowserForProfileChange(workspaceBrowser(workspace), workspace.id);
    return changeWorkspace('replace', { confirm: true, id: workspace.id });
  }

  async function launchBrowser(body) {
    licensing.assertAllowed();
    assertStartupRecovered();
    confirmed(body);
    const saved = consumePlan('browser', body.token);
    await verifyExit();
    assertRevision(saved.revision);
    if (saved.fingerprint !== state.configHash || saved.payload.port !== state.proxy.port) throw error('CONFIRMATION_INVALID', ERROR_MESSAGES.CONFIRMATION_INVALID, 400);
    if (saved.payload.workspaceId) {
      const workspace = await workspaces.assertBinding(saved.payload.workspaceId, (await workspaceConfiguration()).binding);
      if (workspaceBrowser(workspace) !== saved.payload.browserId) throw error('CONFIRMATION_INVALID', ERROR_MESSAGES.CONFIRMATION_INVALID, 400);
    }
    if (saved.browserRegion) {
      if (!equalIp(saved.browserRegion.exitIp, state.proxy.exit.ip)) throw error('CONFIRMATION_INVALID', ERROR_MESSAGES.CONFIRMATION_INVALID, 400);
      const settings = await fingerprintSettings({ refresh: saved.browserRegion.languageAuto || saved.browserRegion.timezoneAuto,
        ...(saved.payload.workspaceId ? { identity: await workspaceIdentity(saved.payload.workspaceId) } : {}) });
      assertRevision(saved.revision);
      if (saved.browserRegion.languageAuto && settings.resolvedLanguage !== saved.payload.language
        || saved.browserRegion.timezoneAuto && settings.resolvedTimezone !== saved.payload.fingerprint.timezone) throw error('CONFIRMATION_INVALID', ERROR_MESSAGES.CONFIRMATION_INVALID, 400);
    }
    licensing.assertAllowed();
    const result = await browsers.launch(saved.payload);
    state.browser = await browsers.status();
    assertRevision(saved.revision);
    return result;
  }

  async function runProbes(body) {
    const exit = await verifyExit({ force: true });
    const revision = state.revision;
    if (body.multi === true) {
      const { config } = await assertActive();
      const report = await createNetworkReport({ exit, expectedExitIps: config.probe.expectedExitIps, proxyPort: state.proxy.port, request, mock, includeSites: body.thirdParty !== false, assertCurrent: () => assertRevision(revision) });
      assertRevision(revision);
      latestReport = { ...report, exit: publicStatus().proxy.exit }; reportRevision = revision;
      if (report.summary.status === 'fail') {
        const cause = error('MULTI_EXIT_MISMATCH', ERROR_MESSAGES.MULTI_EXIT_MISMATCH);
        await blockFailedSession(cause); throw cause;
      }
      return latestReport;
    }
    const results = [exit];
    if (body.thirdParty === true) for (const site of THIRD_PARTY) {
      assertRevision(revision);
      const started = now();
      try {
        const response = mock ? null : await request(new URL(site.url), { proxyPort: state.proxy.port, timeoutMs: 10_000, method: 'HEAD', responseDetails: true });
        assertRevision(revision);
        results.push({ ...site, status: mock ? 'mocked' : response?.statusCode >= 400 ? 'restricted' : 'reachable', elapsedMs: now() - started, scope: '辅助站点连通性，不代表 Claude 业务可用' });
      } catch (cause) {
        assertRevision(revision);
        results.push({ ...site, status: 'failed', errorCode: 'SITE_UNREACHABLE', elapsedMs: now() - started });
      }
    }
    const reachable = results.filter(item => ['verified', 'reachable'].includes(item.status)).length;
    return { generatedAt: timestamp(), results, exit: publicStatus().proxy.exit, summary: { total: results.length, reachable, status: mock ? 'mocked' : reachable === results.length ? 'pass' : 'partial' } };
  }

  const applicationChecks = new Map();
  async function checkApplicationTargets(body = {}) {
    if (Object.keys(body).some(key => !['service', 'path', 'force'].includes(key)) || !Object.hasOwn(APPLICATION_TARGETS, body.service)
      || !['proxy', 'system'].includes(body.path) || body.force !== undefined && typeof body.force !== 'boolean') throw error('APPLICATION_TARGET_INVALID', ERROR_MESSAGES.APPLICATION_TARGET_INVALID, 400);
    const signal = sessionAbort.signal;
    checkCanceled(signal);
    const lease = await applicationProxyLease();
    checkCanceled(signal);
    if (!mock && body.path === 'system' && (lease.coverage.mode !== 'tun' || !lease.coverage.systemExitVerified)) throw error('APPLICATION_SYSTEM_UNVERIFIED', ERROR_MESSAGES.APPLICATION_SYSTEM_UNVERIFIED);
    const key = JSON.stringify([exitBinding(state.configHash), body.service, body.path]);
    const previous = applicationChecks.get(key);
    if (body.force === false && previous && now() >= previous.checkedAt && now() - previous.checkedAt < 60_000) return { ...previous.result, reused: true };
    const revision = state.revision;
    if (!mock && body.path === 'system') {
      await refreshProtectedRuntime();
      const coverage = applicationCoverage();
      if (coverage.mode !== 'tun' || !coverage.systemExitVerified) throw error('APPLICATION_SYSTEM_UNVERIFIED', ERROR_MESSAGES.APPLICATION_SYSTEM_UNVERIFIED);
    }
    const allowedCodes = ['PROXY_TIMEOUT', 'PROXY_CONNECT_REJECTED', 'PROXY_UNREACHABLE', 'PROXY_CLOSED', 'PROXY_RESPONSE_INVALID', 'PROBE_TIMEOUT', 'PROBE_TLS_OR_SOCKET_FAILED', 'PROBE_REQUEST_FAILED', 'PROBE_RESPONSE_FAILED', 'SYSTEM_DNS_FAILED', 'SYSTEM_NETWORK_TIMEOUT', 'SYSTEM_TLS_FAILED', 'SYSTEM_NETWORK_UNREACHABLE'];
    const checks = await Promise.all(APPLICATION_TARGETS[body.service].map(async target => {
      assertRevision(revision);
      const started = now();
      try {
        const response = mock ? null : await cancelableRead((body.path === 'proxy' ? request : systemRequest)(new URL(target), {
          ...(body.path === 'proxy' ? { proxyPort: lease.port } : {}), timeoutMs: 10_000, method: 'HEAD', responseDetails: true, signal,
        }), signal);
        checkCanceled(signal);
        assertRevision(revision);
        const httpStatus = response?.statusCode;
        const reachable = Number.isInteger(httpStatus) && (httpStatus < 400 && httpStatus >= 200 || [401, 404, 405].includes(httpStatus));
        const transportReachable = !mock && Number.isInteger(httpStatus) && httpStatus >= 100 && httpStatus <= 599;
        return { target: new URL(target).hostname, transportReachable, status: mock ? 'mocked' : reachable ? 'reachable' : 'failed', code: mock ? 'MOCKED' : reachable ? 'TARGET_REACHABLE' : [403, 429].includes(httpStatus) ? 'TARGET_HTTP_RESTRICTED' : 'TARGET_HTTP_FAILED', ...(transportReachable ? { stage: 'target-response', targetHttpStatus: httpStatus, httpStatus } : {}), elapsedMs: Math.max(0, now() - started) };
      } catch (cause) {
        checkCanceled(signal);
        assertRevision(revision);
        const code = allowedCodes.includes(cause.code) ? cause.code : 'APPLICATION_TARGET_FAILED';
        const details = sanitizeProbeFailure(cause)?.diagnostic || {};
        diagnostic({ code, operation: `checking-${body.service}-${body.path}`, diagnostic: cause.diagnostic });
        return { target: new URL(target).hostname, transportReachable: false, status: 'failed', code, ...details, elapsedMs: Math.max(0, now() - started) };
      }
    }));
    checkCanceled(signal);
    assertRevision(revision);
    const reachable = checks.filter(check => check.status === 'reachable').length;
    const result = { service: body.service, path: body.path, transportReady: !mock && checks.every(check => check.transportReachable), status: mock ? 'mocked' : reachable === checks.length ? 'reachable' : reachable ? 'partial' : 'failed', code: mock ? 'MOCKED' : reachable === checks.length ? 'APPLICATION_TARGETS_REACHABLE' : 'APPLICATION_TARGETS_FAILED', checks, coverage: applicationCoverage(), observedAt: timestamp(), scope: '仅固定站点 HEAD 连通性与 TLS；HTTP 拒绝与传输就绪分别记录；不请求模型、不检查账号或 OAuth 登录，不跟随重定向。' };
    result.diagnosis = buildLayeredDiagnosis(publicStatus(), result);
    if (result.transportReady) {
      applicationChecks.clear(); applicationChecks.set(key, { checkedAt: now(), result });
    }
    return result;
  }

  async function diagnostics() {
    const systemNetwork = publicStatus().proxy.systemNetwork;
    return { generatedAt: timestamp(), environment: { os: mock ? 'Windows（模拟）' : os.platform(), timezone: mock ? '模拟' : Intl.DateTimeFormat().resolvedOptions().timeZone, locale: mock ? '模拟' : Intl.DateTimeFormat().resolvedOptions().locale }, browsers: await browsers.listBrowsers(), browserLanguage: 'en-US', diagnosis: buildLayeredDiagnosis(publicStatus()), browserObservation: browserObservation.snapshot(), checks: [
      { name: '环境方案', status: environmentState.preferences?.daily ? 'configured' : 'unverified', detail: '工作环境可跟随出口或手动设置；日常环境按已保存方案恢复，原始快照仅用于高级恢复' },
      { name: '系统 TUN', status: systemNetwork.status, detail: systemNetwork.status === 'verified' ? '系统默认 DNS 与路由的 HTTPS 请求已命中指定 ISP 出口；Claude Code、Codex 等应用需重新建立连接，自设代理仍须单独核验' : mock && systemNetwork.status === 'mocked' ? '离线模拟，未核验真实系统网络' : '系统默认网络出口尚未核验；本地代理可用不能证明普通应用已走 TUN' },
      { name: 'DNS 防护', status: state.proxy.protections?.dnsHijack ? 'configured' : 'unverified', detail: 'TUN 劫持 53 端口 DNS，DoH 经 ISP；本机真实泄露测试待完成' },
      { name: 'WebRTC 非代理 UDP', status: state.browser.webrtc?.configured ? 'configured' : 'unverified', detail: state.browser.webrtc?.restartRequired ? '当前窗口使用旧配置，请安全结束并重新启动；WebRTC 地址仍须在独立窗口内复测' : '新会话同时设置 Chromium profile 策略和启动参数；尚未完成当前浏览器 ICE 实测，可能影响语音或视频通话' },
      { name: '故障断网锁', status: networkLockState.locked ? (mock ? 'mocked' : 'configured') : 'unverified', detail: '持久 Windows 防火墙策略；停止代理后保持，需显式解锁。真实 core 强退及既有连接仍需实测' },
      { name: 'Claude Code 清理', status: 'available', detail: '先预览路径与清理范围，再手动确认；运行中拒绝清理' },
    ] };
  }

  async function environmentGeography() {
    const signal = sessionAbort.signal;
    checkCanceled(signal);
    await verifyExit();
    const revision = state.revision;
    const { config, fingerprint } = await assertActive();
    const observed = state.proxy.exit;
    const binding = exitBinding(fingerprint);
    const assertCurrent = () => {
      checkCanceled(signal);
      assertRevision(revision);
      if (state.configHash !== fingerprint || exitBinding(fingerprint) !== binding || !freshObservation(state.proxy.exit, fingerprint)
        || !equalIp(state.proxy.exit.ip, observed.ip)) throw error('SESSION_CHANGED', ERROR_MESSAGES.SESSION_CHANGED);
    };
    assertCurrent();
    const report = reportRevision === revision && publicStatus().report?.stale === false ? latestReport : null;
    const cached = report?.summary.consistent && report.geo?.verified && verifiedExitGeography(report.geo, observed.ip, config.probe.expectedExitIps) ? report.geo : null;
    try {
      let geo, locationError;
      try {
        geo = mock ? { countryCode: 'JP', city: 'Tokyo', timezone: 'Asia/Tokyo', ip: observed.ip, verified: true }
          : cached || await cancelableRead(requestExitGeography({ exitIp: observed.ip, expectedExitIps: config.probe.expectedExitIps, proxyPort: config.listen.port,
            request: (url, settings) => request(url, { ...settings, signal }), assertCurrent }), signal);
      } catch (cause) { locationError = cause; }
      checkCanceled(signal);
      // Geography must not authorize settings after a stopped, replaced or
      // externally edited core/config, even if the HTTP response was valid.
      const latest = await assertActive();
      if (latest.fingerprint !== fingerprint) throw error('PROXY_CONFIG_CHANGED', ERROR_MESSAGES.PROXY_CONFIG_CHANGED);
      if (state.proxy.mode === 'tun') await refreshProtectedRuntime();
      assertCurrent();
      if (locationError) throw locationError;
      if (!mock) browserGeography = { geo, ip: observed.ip, binding, checkedAt: now() };
      return geo;
    } catch (cause) {
      if (!closing && !state.proxy.requestedStop && revision === state.revision && ['PROXY_CONFIG_CHANGED', 'PROXY_OFFLINE', 'TUN_NOT_READY'].includes(cause.code)) await blockFailedSession(cause);
      throw cause;
    }
  }

  async function optimizeEnvironment(body) {
    confirmed(body);
    try {
      const geo = environment.status().preferences?.work?.mode === 'custom' ? null : await environmentGeography();
      environmentState = await environment.optimize({ geo, localize: true, force: true });
      reportPartialEnvironment(environmentState);
    } catch (cause) { await recordEnvironmentFailure(cause, cause.code === 'GEO_UNVERIFIED' ? 'exit-location' : undefined); throw cause; }
    return environmentState;
  }
  function reportPartialEnvironment(result) {
    if (result.optimization?.status === 'partial') diagnostic({ code: 'ENVIRONMENT_PARTIAL', operation: 'environment-optimization', diagnostic: { environmentFields: result.optimization.differingFields } });
  }

  async function cleanupPreview(body) {
    const plan = await browsers.cleanupPreview({ browser: body.browser || 'chrome', items: body.items });
    const token = storePlan('cleanup', plan);
    return { ...token, browser: plan.browser, targets: plan.targets.map(({ path: ignored, ...item }) => item), preserves: plan.preserves, warning: '清除 Cookie 会退出该独立浏览器的网站登录；不自动备份登录令牌。' };
  }

  function checkRequest(req) {
    const ownPort = req.socket.localPort;
    if (![`127.0.0.1:${ownPort}`, `localhost:${ownPort}`].includes(String(req.headers.host || '').toLowerCase())) throw error('HOST_REJECTED', '只允许本机控制服务地址', 403);
    const origin = req.headers.origin;
    if (origin && ![`http://127.0.0.1:${ownPort}`, `http://localhost:${ownPort}`].includes(origin)) throw error('ORIGIN_REJECTED', '拒绝跨站控制请求', 403);
    if (req.headers['sec-fetch-site'] && !['same-origin', 'none'].includes(req.headers['sec-fetch-site'])) throw error('ORIGIN_REJECTED', '拒绝跨站控制请求', 403);
    if (req.method === 'POST' && !/^application\/json(?:\s*;.*)?$/i.test(req.headers['content-type'] || '')) throw error('CONTENT_TYPE_INVALID', '控制操作只接受 JSON', 415);
  }
  async function readBody(req, limit = 32_768) {
    const chunks = []; let size = 0;
    for await (const chunk of req) { size += chunk.length; if (size > limit) throw error('BODY_TOO_LARGE', '请求体过大', 413); chunks.push(chunk); }
    let body;
    try { body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch { throw error('JSON_INVALID', 'JSON 请求无效', 400); }
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw error('JSON_INVALID', '请求必须是 JSON 对象', 400);
    return body;
  }
  async function staticFile(url, req, res) {
    if (!['GET', 'HEAD'].includes(req.method)) throw error('METHOD_NOT_ALLOWED', '不支持此请求方法', 405);
    const reportRoute = /^\/reports\/quality\/([a-f0-9-]{36})\/(cleanip|ippure|ping0)$/.exec(url.pathname);
    if (reportRoute) {
      const contents = await qualityReports.read(reportRoute[1], reportRoute[2]);
      if (!contents) throw error('NOT_FOUND', '报告不存在或已删除', 404);
      res.setHeader('content-type', 'text/html; charset=utf-8');
      return res.end(req.method === 'HEAD' ? undefined : contents);
    }
    const files = { "/layout-preferences.js": "layout-preferences.js", "/layout-preferences.css": "layout-preferences.css", '/': 'index.html', '/index.html': 'index.html', '/app.js': 'app.js', '/controller-client.js': 'controller-client.js', '/workspace-view.js': 'workspace-view.js', '/styles.css': 'styles.css', '/surfaces.css': 'surfaces.css', '/cosmos.css': 'cosmos.css', '/cosmos-surfaces.css': 'cosmos-surfaces.css', '/quality-report.css': 'quality-report.css', '/assets/mc-proxy.svg': 'assets/mc-proxy.svg', '/assets/icons.svg': 'assets/icons.svg', '/assets/mc-proxy-256.png': 'assets/mc-proxy-256.png', '/assets/mc-proxy-512.png': 'assets/mc-proxy-512.png', '/assets/mc-proxy.ico': 'assets/mc-proxy.ico', '/assets/MonaSans-VF.woff2': 'assets/MonaSans-VF.woff2', '/assets/earth-nasa-globe-east.jpg': 'assets/earth-nasa-globe-east.jpg' };
    files['/license-page.js'] = 'license-page.js'; files['/license-page.css'] = 'license-page.css';
    files['/licensing-admin-page.js'] = 'licensing-admin-page.js'; files['/licensing-admin-page.css'] = 'licensing-admin-page.css';
    files['/browser-tools.js'] = 'browser-tools.js'; files['/browser-tools.css'] = 'browser-tools.css';
    files['/dom-updates.js'] = 'dom-updates.js';
    files['/environment-feedback.js'] = 'environment-feedback.js';
    files['/experience-tools.js'] = 'experience-tools.js'; files['/experience-tools.css'] = 'experience-tools.css';
    // Bundled brand assets use the same explicit allowlist as the rest of the UI.
    // Keep metadata and arbitrary files in this directory private.
    for (const brand of ['chatgpt.png', 'chrome.png', 'claude.png', 'codex.png', 'edge.png', 'github.svg', 'google.png', 'wikipedia.png', 'youtube.png']) {
      files[`/assets/brands/${brand}`] = `assets/brands/${brand}`;
    }
    const file = files[url.pathname];
    if (!file) throw error('NOT_FOUND', '页面不存在', 404);
    const contents = await readFile(path.join(frontendRoot, file));
    const mimeTypes = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.jpg': 'image/jpeg' };
    res.setHeader('content-type', mimeTypes[path.extname(file)] || 'application/octet-stream');
    res.end(req.method === 'HEAD' ? undefined : contents);
  }

  const server = http.createServer(async (req, res) => {
    res.setHeader('content-type', 'application/json; charset=utf-8');
    res.setHeader('cache-control', 'no-store');
    res.setHeader('x-content-type-options', 'nosniff');
    res.setHeader('x-frame-options', 'DENY');
    res.setHeader('referrer-policy', 'no-referrer');
    res.setHeader('content-security-policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    let requestAttempt;
    try {
      checkRequest(req);
      const url = new URL(req.url, 'http://127.0.0.1');
      if (!url.pathname.startsWith('/api/')) return await staticFile(url, req, res);
      const credential = req.headers['x-mc-control-token'];
      if (typeof credential !== 'string' || !/^[a-f0-9]{64}$/i.test(credential) || !timingSafeEqual(Buffer.from(credential, 'hex'), Buffer.from(controlToken, 'hex'))) {
        throw error('CONTROL_AUTH_REQUIRED', '控制会话身份无效，请重新打开 MC Proxy；控制台模式请使用启动器提供的完整链接', 401);
      }
      // Cloud licensing work is deliberately independent of the routing queue.
      // A slow refresh cannot hold status, disconnect, repair or environment restore.
      if (url.pathname.startsWith('/api/license/')) {
        // Keep read/recovery access responsive, but don't let a separate import
        // race the explicit delivery commit's final signed-license write.
        if (req.method === 'POST' && deliveryRevision !== null) throw error('DELIVERY_BUSY', ERROR_MESSAGES.DELIVERY_BUSY, 409);
        let result;
        if (req.method === 'GET' && url.pathname === '/api/license/status') result = licensing.status();
        else if (req.method === 'GET' && url.pathname === '/api/license/device') {
          const application = licensing.deviceApplication();
          result = { application: typeof application === 'string' ? JSON.parse(application) : application };
        } else if (req.method === 'POST' && ['/api/license/activate', '/api/license/import', '/api/license/refresh'].includes(url.pathname)) {
          if (closing) throw error('SERVICE_STOPPING', '控制服务正在安全关闭', 503);
          const body = await readBody(req);
          const field = url.pathname.endsWith('/activate') ? 'card' : url.pathname.endsWith('/import') ? 'text' : null;
          if (Object.keys(body).some(key => key !== field) || field && typeof body[field] !== 'string') throw error('INPUT_INVALID', '授权请求格式无效', 400);
          result = field === 'card' ? await licensing.activate(body.card) : field === 'text' ? await licensing.importLicense(body.text) : await licensing.refresh();
        } else throw error('NOT_FOUND', '授权接口不存在', 404);
        if (!req.aborted && !res.destroyed) res.end(JSON.stringify(success(result)));
        return;
      }
      // Browser measurements and optional engine downloads are independent of
      // the routing queue. They cannot hold disconnect or network recovery.
      if (req.method === 'GET' && ['/api/browser-observation', '/api/browser/fingerprint'].includes(url.pathname)) {
        if (closing) throw error('SERVICE_STOPPING', ERROR_MESSAGES.SERVICE_STOPPING, 503);
        const result = url.pathname === '/api/browser-observation' ? browserObservation.snapshot() : await fingerprintStatus();
        if (!req.aborted && !res.destroyed) res.end(JSON.stringify(success(result)));
        return;
      }
      if (req.method === 'POST' && url.pathname === '/api/browser/fingerprint/install') {
        const result = await installFingerprint(await readBody(req));
        if (!req.aborted && !res.destroyed) res.end(JSON.stringify(success(result)));
        return;
      }
      if (req.method === 'POST' && url.pathname === '/api/browser/fingerprint/security') {
        if (closing) throw error('SERVICE_STOPPING', ERROR_MESSAGES.SERVICE_STOPPING, 503);
        const body = await readBody(req);
        if (Object.keys(body).some(key => key !== 'confirm')) throw error('INPUT_INVALID', '安全版本检查不接受地址或下载参数', 400);
        confirmed(body);
        const security = await fingerprintSecurity.check();
        if (!req.aborted && !res.destroyed) res.end(JSON.stringify(success({ security })));
        return;
      }
      if (repairPending && url.pathname !== '/api/progress') {
        if (req.method === 'GET' && ['/api/status', '/api/state', '/api/snapshot'].includes(url.pathname)) return res.end(JSON.stringify(success(publicStatus())));
        throw error('SERVICE_REPAIRING', '网络修复正在进行，请等待结果后再操作', 503);
      }
      let action;
      if (req.method === 'GET') {
        // Observation has its own generation/ownership checks and cannot mutate
        // routing. It must not make normal status reads busy behind UI polling.
        if (url.pathname === '/api/connections') {
          if (closing) throw error('SERVICE_STOPPING', '控制服务正在安全关闭', 503);
          const result = await (runtime.connections?.() || { status: 'unavailable', active: 0, observed: 0, connections: [] });
          if (!req.aborted && !res.destroyed) res.end(JSON.stringify(success(result)));
          return;
        }
        // Progress is a cached read, never queued behind a long firewall check.
        if (url.pathname === '/api/progress') return res.end(JSON.stringify(success({ phase: state.phase, operation: state.operation, vpnLatency: publicVpnLatency(),
          connectionCancellation: { active: Boolean(connectionAttempt), requested: connectionAttempt?.controller.signal.aborted === true } })));
        if (url.pathname === '/api/snapshot') return res.end(JSON.stringify(success(publicStatus())));
        if (['/api/status', '/api/state'].includes(url.pathname)) {
          // Polls never queue another native read behind an operation or an
          // existing status refresh. These snapshots authorize no app launch.
          if (queuedOperations || statusRefresh) return res.end(JSON.stringify(success(publicStatus())));
          if (req.aborted || res.destroyed) return;
          const reading = serialized(() => req.aborted || res.destroyed ? undefined : status());
          statusRefresh = reading;
          try {
            const result = await reading;
            if (!req.aborted && !res.destroyed) res.end(JSON.stringify(success(result)));
          } finally { if (statusRefresh === reading) statusRefresh = null; }
          return;
        }
        else if (url.pathname === '/api/onboarding') action = onboardingStatus;
        else if (url.pathname === '/api/workspaces') action = workspaceStatus;
        else if (url.pathname === '/api/browser/profiles') {
          if ([...url.searchParams.keys()].some(key => key !== 'browser') || url.searchParams.getAll('browser').length !== 1) throw error('INPUT_INVALID', '浏览器资料查询无效', 400);
          action = () => browserProfiles(url.searchParams.get('browser'));
        }
        else if (url.pathname === '/api/reminders') action = remindersStatus;
        else if (url.pathname === '/api/diagnostics') action = diagnostics;
        else if (url.pathname === '/api/diagnostics/summary') action = () => createDiagnosticShareSummary({ version: options.appVersion, status: publicStatus() });
        else if (url.pathname === '/api/relay') action = refreshRelay;
        else if (url.pathname === '/api/vpn/config') action = refreshVpnConfig;
        else if (url.pathname === '/api/probes') throw error('METHOD_NOT_ALLOWED', '请通过界面按钮显式发起检测', 405);
      } else if (req.method === 'POST') {
        const body = await readBody(req, url.pathname === '/api/delivery/preview' ? 2 * CUSTOMER_DELIVERY_MAX_BYTES + 32_768 : url.pathname === '/api/vpn/import' ? 2 * 1024 * 1024 + 32_768 : 32_768);
        if (url.pathname.startsWith('/api/optimization/') || body.items?.includes?.('claudeData')) throw error('FEATURE_UNAVAILABLE', '请使用独立的环境管理或 Claude Code 清理入口', 410);
        if (url.pathname === '/api/proxy/start') {
          if (connectionAttempt) throw error('CONNECTION_IN_PROGRESS', ERROR_MESSAGES.CONNECTION_IN_PROGRESS, 409);
          const requestedRevision = state.revision;
          const attempt = { controller: new AbortController() }; connectionAttempt = requestAttempt = attempt;
          action = async () => { try { return await startProxy(body, requestedRevision, attempt.controller.signal); } finally { if (connectionAttempt === attempt) connectionAttempt = null; } };
        }
        else if (url.pathname === '/api/workspaces/start') {
          if (connectionAttempt) throw error('CONNECTION_IN_PROGRESS', ERROR_MESSAGES.CONNECTION_IN_PROGRESS, 409);
          const requestedRevision = state.revision;
          const attempt = { controller: new AbortController() }; connectionAttempt = requestAttempt = attempt;
          action = async () => { try { return await startWorkspace(body, requestedRevision, attempt.controller.signal); } finally { if (connectionAttempt === attempt) connectionAttempt = null; } };
        }
        else if (['/api/workspaces/create', '/api/workspaces/update', '/api/workspaces/remove', '/api/workspaces/archive', '/api/workspaces/restore', '/api/workspaces/replace'].includes(url.pathname)) action = () => changeWorkspace(url.pathname.split('/').at(-1), body);
        else if (url.pathname === '/api/reminders/save') action = () => saveReminder(body);
        else if (url.pathname === '/api/delivery/preview') action = () => previewDelivery(body);
        else if (url.pathname === '/api/delivery/import') action = () => importDelivery(body);
        else if (url.pathname === '/api/support/report') action = () => {
          if (Object.keys(body).length) throw error('INPUT_INVALID', '故障报告不接受配置、路径或额外参数', 400);
          return supportReport();
        };
        else if (url.pathname === '/api/proxy/resume') {
          if (Object.keys(body).some(key => key !== 'confirm')) throw error('INPUT_INVALID', '恢复代理连接不接受额外选项', 400);
          confirmed(body);
          if (connectionAttempt) throw error('CONNECTION_IN_PROGRESS', ERROR_MESSAGES.CONNECTION_IN_PROGRESS, 409);
          const attempt = { controller: new AbortController() }; connectionAttempt = requestAttempt = attempt;
          action = async () => { try { return await resumePaidSession(attempt.controller.signal); } finally { if (connectionAttempt === attempt) connectionAttempt = null; } };
        }
        else if (['/api/session/end', '/api/proxy/stop'].includes(url.pathname)) {
          confirmed(body);
          cancelSessionWork(); invalidate(); state.proxy.requestedStop = true;
          action = endSession;
        } else if (url.pathname === '/api/browsers/rescan' || url.pathname === '/api/browsers/path') action = async () => {
          const setting = url.pathname === '/api/browsers/path';
          const fields = setting ? ['browser', 'executable', 'confirm'] : [];
          if (Object.keys(body).some(key => !fields.includes(key))) throw error('INPUT_INVALID', '浏览器识别请求包含未知选项', 400);
          if (setting) {
            confirmed(body);
            if (!browsers.setExecutable) throw error('FEATURE_UNAVAILABLE', '当前浏览器管理器不支持指定安装路径', 409);
            browserOptions = await browsers.setExecutable({ browser: body.browser, executable: body.executable });
          } else browserOptions = await browsers.rescan?.() || await browsers.listBrowsers();
          invalidateBrowserPlans();
          return { browserOptions };
        };
        else if (url.pathname === '/api/browser/plan') action = () => browserPlan(body);
        else if (url.pathname === '/api/browser/profiles/refresh') action = () => changeBrowserProfile('refresh', body);
        else if (url.pathname === '/api/browser/profiles/restore') action = () => changeBrowserProfile('restore', body);
        else if (url.pathname === '/api/workspaces/refresh') action = () => refreshWorkspaceProfile(body);
        else if (url.pathname === '/api/browser-observation/start') action = () => startBrowserObservation(body);
        else if (url.pathname === '/api/browser/fingerprint/rotate') action = () => rotateFingerprint(body);
        else if (url.pathname === '/api/browser/fingerprint/settings') action = async () => {
          if (Object.keys(body).some(key => !['confirm', 'language', 'timezone', 'nativeGraphics'].includes(key))) throw error('INPUT_INVALID', '浏览器地区设置包含未知选项', 400);
          confirmed(body); assertStartupRecovered();
          try {
            await onboarding.preferences({ ...(body.language !== undefined ? { fingerprintLanguage: body.language } : {}), ...(body.timezone !== undefined ? { fingerprintTimezone: body.timezone } : {}), ...(body.nativeGraphics !== undefined ? { fingerprintNativeGraphics: body.nativeGraphics } : {}) });
          } catch (cause) {
            if (cause.code === 'ONBOARDING_PREFERENCES_INVALID') throw error(cause.code, ERROR_MESSAGES[cause.code], 400);
            throw cause;
          }
          invalidateBrowserPlans(); browserObservation.invalidate();
          return fingerprintStatus();
        };
        else if (url.pathname === '/api/browser/launch') action = () => launchBrowser(body);
        else if (url.pathname === '/api/browser/close') {
          confirmed(body); invalidateBrowserPlans();
          action = async () => {
            invalidateBrowserPlans(); browserObservation.invalidate();
            let result;
            try { result = await browsers.close(); }
            catch (cause) { try { state.browser = await browsers.status(); } catch {} throw cause; }
            state.browser = await browsers.status(); return result;
          };
        } else if (url.pathname === '/api/probes') action = () => runProbes(body);
        else if (url.pathname === '/api/applications/check') action = () => checkApplicationTargets(body);
        else if (url.pathname === '/api/cleanup/preview') action = () => cleanupPreview(body);
        else if (url.pathname === '/api/cleanup/apply') action = async () => { confirmed(body); return browsers.cleanupApply(consumePlan('cleanup', body.token).payload); };
        else if (url.pathname === '/api/configuration/save') { const revision = state.revision; action = () => saveConfiguration(body, revision); }
        else if (url.pathname === '/api/vpn/import' || url.pathname === '/api/vpn/select') action = async () => {
          const importing = url.pathname === '/api/vpn/import';
          const fields = importing ? ['confirm', 'text', 'expectedId'] : ['confirm', 'nodeIndex', 'expectedId'];
          if (Object.keys(body).some(key => !fields.includes(key))) throw error('INPUT_INVALID', '配置导入或选择包含未知选项', 400);
          confirmed(body); assertStartupRecovered(); await assertSetupIdle();
          if (importing) await vpnConfigStore.import(body.text, { ...(body.expectedId !== undefined ? { expectedId: body.expectedId } : {}) });
          else await vpnConfigStore.select(body.nodeIndex, { ...(body.expectedId !== undefined ? { expectedId: body.expectedId } : {}) });
          invalidate(); compatibilityState = null; vpnLatencyState = null; vpnLatencyCache = null;
          return { vpnConfig: await refreshVpnConfig() };
        };
        else if (url.pathname === '/api/vpn/subscription/refresh' || url.pathname === '/api/vpn/subscription/clear') action = async () => {
          const refreshing = url.pathname.endsWith('/refresh');
          if (Object.keys(body).some(key => !['confirm', 'expectedId', ...(refreshing ? ['url'] : [])].includes(key))) throw error('INPUT_INVALID', '订阅请求包含未知选项', 400);
          confirmed(body); assertStartupRecovered();
          const previous = await vpnConfigStore.status();
          if (refreshing) await subscriptions.refresh({ ...(body.url !== undefined ? { url: body.url } : {}), ...(body.expectedId !== undefined ? { expectedId: body.expectedId } : {}) });
          else await subscriptions.clear({ ...(body.expectedId !== undefined ? { expectedId: body.expectedId } : {}) });
          const updated = await refreshVpnConfig();
          const changed = previous.id !== updated.id;
          if (changed) {
            invalidate(); state.proxy.requestedStop = true; compatibilityState = null; vpnLatencyState = null; vpnLatencyCache = null;
            await endSession();
          }
          return { vpnConfig: updated, sessionEnded: changed };
        };
        else if (url.pathname === '/api/vpn/check' || url.pathname === '/api/vpn/latency') {
          const revision = state.revision;
          const forceLatency = url.pathname === '/api/vpn/latency';
          action = async () => {
            if (Object.keys(body).length) throw error('INPUT_INVALID', '链路检测不接受额外参数', 400);
            assertSetupRevision(revision); await assertSetupIdle();
            if (!(await onboarding.configuration()).available) throw error('ONBOARDING_CONFIGURATION_REQUIRED', ERROR_MESSAGES.ONBOARDING_CONFIGURATION_REQUIRED);
            const config = await readSessionConfiguration();
            if (config.connectionMode !== 'vpn-import') throw error('INPUT_INVALID', '请先保存导入配置模式的 ISP 设置', 400);
            try {
              const checked = await verifyImportedConfiguration({ config, secrets: mock ? {} : await readSavedSecrets(config) }, revision, { forceLatency });
              return { checks: checked.result.checks, compatibility: compatibilityState, vpnConfig: await refreshVpnConfig(), vpnLatency: publicVpnLatency() };
            } finally { state.operation = null; }
          };
        }
        else if (url.pathname === '/api/relay/import') action = async () => {
          if (Object.keys(body).some(key => !['confirm', 'enrollment'].includes(key))) throw error('INPUT_INVALID', '中转导入包含未知选项', 400);
          confirmed(body); assertStartupRecovered(); await assertSetupIdle();
          await relayManager.importEnrollment(body.enrollment); invalidate();
          return { ...await refreshRelay(), ...await refreshDiagnosticsAfterSave() };
        };
        else if (url.pathname === '/api/relay/check') action = async () => {
          if (Object.keys(body).length) throw error('INPUT_INVALID', '中转检测不接受额外参数', 400);
          assertStartupRecovered(); await assertSetupIdle();
          try { return { ...await relayManager.check(), required: requireRelay }; }
          finally { await refreshRelay(); }
        };
        else if (url.pathname === '/api/diagnostics/export') action = async () => {
          if (Object.keys(body).length) throw error('INPUT_INVALID', '诊断导出不接受路径或额外参数', 400);
          return exportDiagnostics();
        };
        else if (url.pathname === '/api/network/cache/recover') action = async () => {
          if (Object.keys(body).some(key => !['confirm', 'applicationsClosed'].includes(key)) || body.applicationsClosed !== true) throw error('INPUT_INVALID', '映射恢复须先明确确认已关闭受影响的浏览器与应用', 400);
          confirmed(body); assertStartupRecovered(); await assertSetupIdle({ allowRetainedLock: true });
          if (!runtime.recoverFakeIpCache) throw error('FEATURE_UNAVAILABLE', '当前核心未提供受管映射恢复', 409);
          const result = await runtime.recoverFakeIpCache({ confirm: true, applicationsClosed: true });
          invalidate(); networkLifecycle = { state: 'stable', reason: null }; state.phase = 'idle'; state.lastError = null;
          return { recovered: result.recovered === true, archived: result.archived === true, mock: mock || result.mock === true || result.status === 'mocked' };
        };
        else if (url.pathname === '/api/onboarding/preferences') action = async () => {
          assertStartupRecovered();
          const result = await onboarding.preferences(body);
          if (['fingerprintLanguage', 'fingerprintTimezone', 'fingerprintNativeGraphics', 'fingerprintFresh'].some(key => Object.hasOwn(body, key))) invalidateBrowserPlans();
          return result;
        };
        else if (url.pathname === '/api/quality/check') { const revision = state.revision; action = () => checkQuality(revision, body); }
        else if (url.pathname === '/api/environment/check') action = () => checkEnvironment(body);
        else if (url.pathname === '/api/environment/adopt') action = () => adoptCurrentEnvironment(body);
        else if (url.pathname === '/api/environment/preferences') action = async () => {
          confirmed(body);
          if (Object.keys(body).some(key => !['confirm', 'work', 'daily'].includes(key))) throw error('INPUT_INVALID', '环境方案包含未知选项', 400);
          try { environmentState = await environment.savePreferences({ work: body.work, daily: body.daily }); }
          catch (cause) {
            if (cause.code === 'ENVIRONMENT_PROFILE_INVALID') throw error(cause.code, cause.message, 400);
            if (['ENVIRONMENT_PROFILE_FOREIGN', 'ENVIRONMENT_PROFILE_CONFLICT'].includes(cause.code)) throw error(cause.code, cause.message, 409);
            throw cause;
          }
          return environmentState;
        };
        else if (url.pathname === '/api/environment/optimize') action = () => optimizeEnvironment(body);
        else if (url.pathname === '/api/environment/restore') action = async () => { confirmed(body); try { environmentState = await environment.restore(); reportPartialEnvironment(environmentState); } finally { environmentState = environment.status(); } return environmentState; };
        else if (url.pathname === '/api/environment/restore-original') action = async () => { confirmed(body); try { environmentState = await environment.restore({ original: true }); reportPartialEnvironment(environmentState); } finally { environmentState = environment.status(); } return environmentState; };
        else if (url.pathname === '/api/claude/cleanup-plan') action = async () => {
          const plan = await claudeCleanup.preview();
          return { plan: { ...plan, token: plan.confirmationToken } };
        };
        else if (url.pathname === '/api/claude/cleanup') action = async () => {
          confirmed(body);
          return claudeCleanup.confirm({ confirmationToken: body.token || body.planId, confirmed: true });
        };
        else if (url.pathname === '/api/network-lock/arm') action = async () => {
          if (Object.keys(body).some(key => key !== 'confirm')) throw error('INPUT_INVALID', '开启断网锁不接受额外参数', 400);
          confirmed(body); assertStartupRecovered();
          if (runtime.networkLock?.canArm === false) throw error('NETWORK_LOCK_DISABLED', ERROR_MESSAGES.NETWORK_LOCK_DISABLED);
          await verifyExit();
          if (state.proxy.mode !== 'tun') throw error('NETWORK_LOCK_TUN_REQUIRED', ERROR_MESSAGES.NETWORK_LOCK_TUN_REQUIRED);
          if (!runtime.armNetworkLock) throw error('NETWORK_LOCK_UNAVAILABLE', '当前运行时没有可管理的断网锁');
          state.operation = { stage: 'locking-network', message: '正在手动开启断网锁并重新核验连接…', at: timestamp() };
          try {
            await runtime.armNetworkLock();
            await refreshNetworkLock();
            await verifyExit({ force: true });
            return publicStatus();
          } catch (cause) {
            await blockFailedSession(cause);
            throw cause;
          } finally { state.operation = null; }
        };
        else if (url.pathname === '/api/network-lock/unlock') action = async () => {
          confirmed(body);
          const live = await runtime.status();
          const browser = await browsers.status();
          if (live.running || browser.running) throw error('NETWORK_LOCK_ACTIVE', '请先安全结束代理和独立浏览器会话，再解除断网锁');
          if (!runtime.networkLock) throw error('NETWORK_LOCK_UNAVAILABLE', '当前运行时没有可管理的断网锁');
          await runtime.assertSafeToUnlock?.();
          try {
            const result = await runtime.networkLock.unlock({ confirm: true });
            await refreshNetworkLock();
            return { ...result, networkLock: networkLockState };
          } finally { state.operation = null; }
        };
      }
      if (!action) throw error('NOT_FOUND', '接口不存在', 404);
      if (closing) throw error('SERVICE_STOPPING', '控制服务正在安全关闭', 503);
      const result = await serialized(() => {
        if (req.method === 'GET' && (req.aborted || res.destroyed)) return;
        // Shutdown can begin while this request is waiting behind another
        // operation. Do not run a queued mutation after that intent is set.
        if (closing) throw error('SERVICE_STOPPING', '控制服务正在安全关闭', 503);
        if (repairPending) throw error('SERVICE_REPAIRING', '网络修复正在进行，请等待结果后再操作', 503);
        return action();
      });
      if (!req.aborted && !res.destroyed) res.end(JSON.stringify(success(result)));
    } catch (cause) {
      if (requestAttempt && connectionAttempt === requestAttempt) { requestAttempt.controller.abort(cause); connectionAttempt = null; }
      const custom = typeof cause.status === 'number' && cause.status >= 400 && cause.status <= 599;
      const code = custom && /^[A-Z_]+$/.test(cause.code || '') ? cause.code : failureCode(cause);
      if (code !== 'CONTROL_AUTH_REQUIRED') diagnostic({ code, operation: state.operation?.stage || state.phase, diagnostic: cause.diagnostic });
      res.statusCode = custom ? cause.status : 500;
      const unsupportedNodes = code === 'VPN_IMPORT_NO_SUPPORTED_NODES' && Array.isArray(cause.unsupportedNodes)
        ? cause.unsupportedNodes.filter(node => Number.isInteger(node?.index) && node.index >= 1 && node.index <= 256
          && typeof node.code === 'string' && /^VPN_NODE_[A-Z_]{1,60}$/.test(node.code)).slice(0, 256).map(({ index, code }) => ({ index, code })) : [];
      const environmentDetails = code.startsWith('ENVIRONMENT_') ? sanitizeEnvironmentDiagnostic(cause.diagnostic) : null;
      const setupDetails = sanitizeSetupDiagnostic(cause.diagnostic);
      res.end(JSON.stringify({ ok: false, error: { code, message: ERROR_MESSAGES[code] || (custom ? cause.message : ERROR_MESSAGES.OPERATION_FAILED),
        ...(unsupportedNodes.length ? { details: { unsupportedNodes } } : environmentDetails || setupDetails ? { details: { ...environmentDetails, ...setupDetails } } : {}) } }));
    }
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 10_000;
  server.state = state;
  server.runtime = runtime;
  // Only trusted in-process callers receive the credential. Static assets and
  // status payloads never bootstrap another local process into this session.
  server.controlHeaders = () => ({ 'x-mc-control-token': controlToken });
  server.createSupportReport = () => serialized(supportReport);
  server.controlUrl = () => `http://127.0.0.1:${server.address().port}/#control_token=${controlToken}`;
  // Trusted desktop IPC uses the same owned-core and pinned-exit checks as the
  // dedicated browser. A listening port alone cannot authorize an app launch.
  async function applicationProxyLease() {
    licensing.assertAllowed();
    if (closing) throw error('SERVICE_STOPPING', '控制服务正在安全关闭', 503);
    if (repairPending) throw error('SERVICE_REPAIRING', '网络修复正在进行，请等待结果', 503);
    assertStartupRecovered();
    await verifyExit();
    const revision = state.revision;
    const { config, fingerprint } = await loadConfiguration();
    assertRevision(revision);
    const currentProof = () => freshObservation(state.proxy.exit, fingerprint) && (state.proxy.mode !== 'tun' || freshObservation(state.proxy.systemExit, fingerprint));
    licensing.assertAllowed();
    if (!currentProof()) {
      throw error('EXIT_UNVERIFIED', ERROR_MESSAGES.EXIT_UNVERIFIED);
    }
    const port = config.listen.port;
    const gatewayWasRunning = applicationGateway.status().running === true;
    try {
      const endpoint = mock ? { port, endpoint: `127.0.0.1:${port}`, url: `http://127.0.0.1:${port}`, policy: 'private-direct-public-isp' }
        : await applicationGateway.start({ upstreamPort: port, revision });
      assertRevision(revision);
      licensing.assertAllowed();
      if (!currentProof()) throw error('EXIT_UNVERIFIED', ERROR_MESSAGES.EXIT_UNVERIFIED);
      return { ...endpoint, corePort: port, mode: state.proxy.mode, exitStatus: mock ? 'mocked' : 'verified', coverage: applicationCoverage(), binding: hash(exitBinding(fingerprint)), mock, revision };
    } catch (cause) {
      if (typeof applicationGateway.pause === 'function') applicationGateway.pause();
      else if (cause.code !== 'EXIT_UNVERIFIED' || !gatewayWasRunning) await applicationGateway.stop().catch(() => {});
      throw cause;
    }
  }
  async function refreshProtectedRuntime() {
    try {
      await refreshLocal({ force: true });
      if (!state.proxy.running || !state.proxy.managed) throw error('PROXY_OFFLINE', ERROR_MESSAGES.PROXY_OFFLINE);
    } catch (cause) {
      if (cause.code === 'SESSION_CHANGED') throw cause;
      if (OBSERVATION_FAILURES.has(cause.code)) {
        diagnostic({ code: cause.code, operation: 'checking-local-runtime', diagnostic: cause.diagnostic });
        rememberFailure(cause); healthState = { state: 'degraded', checkedAt: timestamp(), errorCode: state.lastError.code };
      } else if (!closing && !state.proxy.requestedStop) await blockFailedSession(cause);
      throw cause;
    }
  }
  server.applicationProxy = () => serialized(applicationProxyLease);
  server.suspendNetwork = () => {
    if (closing || repairPending) return;
    networkGeneration++; invalidate(); networkLifecycle = { state: 'suspended', reason: 'suspend' };
    diagnostic({ code: 'NETWORK_RECHECK_REQUIRED', operation: 'network-suspended' });
  };
  server.networkChanged = reason => {
    if (!['resume', 'adapter-change'].includes(reason) || closing || repairPending) return Promise.resolve(publicStatus());
    networkGeneration++; invalidate(); networkLifecycle = { state: 'checking', reason };
    if (networkRefresh) return networkRefresh;
    const work = serialized(async () => {
      for (let attempt = 0; attempt < 2; attempt++) {
        if (closing || repairPending || networkLifecycle.state === 'suspended') return publicStatus();
        const generation = networkGeneration;
        if (!state.proxy.running || state.proxy.requestedStop) { networkLifecycle = { state: 'stable', reason }; return publicStatus(); }
        state.operation = { stage: 'verifying-network-change', message: '网络发生变化，正在重新核验当前链路…', at: timestamp() };
        try {
          await verifyExit({ force: true, allowNetworkRefresh: true });
          if (generation === networkGeneration) { networkLifecycle = { state: 'stable', reason }; lastHealthCheck = now(); await resumeApplicationGateway(); return publicStatus(); }
        } catch (cause) {
          if (generation === networkGeneration) {
            networkLifecycle = { state: 'unverified', reason };
            if (!OBSERVATION_FAILURES.has(cause.code) && state.proxy.running && !state.proxy.requestedStop) await blockFailedSession(cause);
            return publicStatus();
          }
        } finally { state.operation = null; }
      }
      if (networkLifecycle.state !== 'suspended') networkLifecycle = { state: 'unverified', reason };
      return publicStatus();
    });
    networkRefresh = work;
    void work.finally(() => { if (networkRefresh === work) networkRefresh = null; }).catch(() => {});
    return work;
  };
  server.checkApplicationTargets = body => serialized(() => checkApplicationTargets(body));
  server.openWebsite = service => serialized(async () => {
    if (!['ping0', 'cleanip', 'ippure', 'claude', 'tiktok'].includes(service)) throw error('SERVICE_INVALID', '仅支持固定受管网站', 400);
    const preferences = await onboarding.status();
    const planned = await browserPlan({ service, browser: preferences.preferences?.browser || 'chrome' });
    return launchBrowser({ token: planned.token, confirm: true });
  });
  server.browsers = browsers;
  server.relayManager = relayManager;
  server.vpnConfigStore = vpnConfigStore;
  server.licensing = licensing;
  server.initializeLicense = () => licensing.initialize();
  server.initialize = () => serialized(async () => {
    // Recover an interrupted two-file save before any main runtime config read.
    startupRecoveryError = null;
    try {
      await deliveryImporter.recover();
      await onboarding.status();
      await setupVerifier.recoverAndStop?.();
    } catch (cause) {
      invalidate(); state.proxy.requestedStop = true; state.initialized = true;
      state.configuration = { available: false, pinned: false, errorCode: 'STARTUP_RECOVERY_REQUIRED' };
      rememberFailure(cause);
      startupRecoveryError = { ...state.lastError };
      return publicStatus();
    }
    state.lastError = null; state.phase = 'idle';
    try { environmentState = await environment.initialize({ checkIfMissing: false }); }
    catch {
      const saved = environment.status();
      environmentState = { ...saved, status: 'failed', warnings: saved.warnings?.length ? saved.warnings : ['无法读取已保存的环境快照，请在第二步重新检查。'] };
    }
    return status();
  });
  server.shutdown = () => {
    if (shutdownWork) return shutdownWork;
    shutdownWork = (async () => {
    if (repairPending) throw error('SERVICE_REPAIRING', '网络修复正在进行，请等待结果后再退出', 503);
    closing = true; fingerprintInstallAbort?.abort(); cancelSessionWork(); invalidate(); state.proxy.requestedStop = true;
    try { await serialized(endSession); }
    catch (cause) { closing = false; throw cause; }
    clearInterval(healthTimer);
    clearInterval(licenseTimer);
    await licensing.close?.();
    await browserObservation.close();
    if (fingerprintInstallWork) await fingerprintInstallWork;
    await new Promise((resolve, reject) => {
      // All owned browser/core work has completed before closing this HTTP
      // controller. Chromium preconnects and partial headers must not keep the
      // desktop process alive until the HTTP request/header timeout expires.
      server.close(cause => cause ? reject(cause) : resolve());
      server.closeIdleConnections();
      server.closeAllConnections();
    });
    await runtime.dispose?.();
    })();
    shutdownWork.catch(() => { shutdownWork = null; });
    return shutdownWork;
  };
  server.beginNetworkRepair = async () => {
    if (closing || repairPending) throw error('SERVICE_REPAIRING', '网络修复或退出正在进行，请等待结果', 503);
    repairPending = true; cancelSessionWork(); invalidate(); state.proxy.requestedStop = true;
    try {
      await serialized(endSession);
      state.operation = { stage: 'repairing-network', message: '正在恢复网络，请等待修复结果…', at: timestamp() };
      return publicStatus();
    } catch (cause) { repairPending = false; throw cause; }
  };
  server.finishNetworkRepair = () => serialized(async () => {
    try {
      await runtime.networkLock?.reload?.();
      await refreshNetworkLock();
      repairPending = false; state.operation = null;
      return publicStatus();
    } catch (cause) { rememberFailure(cause); throw cause; }
  });
  const healthTimer = options.healthIntervalMs === 0 ? null : setInterval(async () => {
    if (closing || repairPending || healthBusy || startupRecoveryError || !blockPending && !['stable', 'unverified'].includes(networkLifecycle.state)) return;
    if (!blockPending && state.initialized && !state.proxy.running) return;
    const interval = healthState.state === 'degraded' ? Math.min(options.healthIntervalMs || 60_000, 10_000) : options.healthIntervalMs || 60_000;
    if (!blockPending && state.initialized && now() - lastHealthCheck < interval) return;
    healthBusy = true;
    const healthRevision = state.revision, healthGeneration = networkGeneration;
    const currentHealth = () => healthRevision === state.revision && healthGeneration === networkGeneration;
    try {
      await (async () => {
        if (closing || repairPending || startupRecoveryError) return;
        if (!state.initialized) return;
        if (blockPending) { await serialized(() => blockFailedSession(state.lastError)); return; }
        if (!state.proxy.running || !['stable', 'unverified'].includes(networkLifecycle.state)) return;
        const recoveringNetwork = networkLifecycle.state === 'unverified';
        healthState = { ...healthState, state: 'checking', errorCode: null };
        try {
          await verifyExit({ allowStopping: true, force: true, background: true, allowNetworkRefresh: recoveringNetwork });
          if (currentHealth() && recoveringNetwork) { networkLifecycle = { ...networkLifecycle, state: 'stable' }; await resumeApplicationGateway(); }
        }
        catch (cause) {
          if (closing || !currentHealth() || !['stable', 'unverified'].includes(networkLifecycle.state) || cause.code === 'NETWORK_RECHECK_REQUIRED') return;
          if (cause.code === 'SESSION_CHANGED') return;
          const observationFailed = OBSERVATION_FAILURES.has(cause.code);
          healthState = { ...healthState, state: observationFailed ? 'degraded' : 'failed', errorCode: Object.hasOwn(ERROR_MESSAGES, cause.code) ? cause.code : 'OPERATION_FAILED' };
          if (!observationFailed) await serialized(() => !currentHealth() || !state.proxy.running ? undefined : blockFailedSession(cause));
        }
      })();
    } catch (cause) { if (currentHealth()) rememberFailure(cause); }
    finally {
      healthBusy = false;
      if (currentHealth()) {
        lastHealthCheck = now();
        healthState = { ...healthState, state: ['failed', 'degraded'].includes(healthState.state) ? healthState.state : 'idle', checkedAt: timestamp() };
      } else if (healthState.state === 'checking') healthState = { state: 'idle', checkedAt: null, errorCode: null };
    }
  }, options.healthIntervalMs || 5_000);
  healthTimer?.unref();
  let licenseBusy = false;
  async function enforceLicense() {
    if (licenseBusy || closing || repairPending || !state.proxy.running || !state.proxy.managed) return;
    const permission = licensing.status();
    if (permission.mode !== 'required' || permission.allowed) return;
    let cause;
    try { licensing.assertAllowed(); } catch (failure) { cause = failure; }
    if (!cause) return;
    if (state.proxy.trafficHoldStatus === 'blocked') return;
    licenseBusy = true;
    // Revoke admission immediately, even if a long startup/optimization is
    // awaiting the network. Its existing revision checks will unwind safely.
    licenseSuspended = cause; cancelSessionWork(cause); invalidate(); state.proxy.requestedStop = true;
    try {
      await serialized(async () => {
        if (closing || repairPending) return;
        await suspendPaidSession(cause);
        if (!licensing.status().allowed && state.proxy.trafficHoldStatus !== 'failed') { rememberFailure(cause); diagnostic({ code: cause.code, operation: 'license-expired' }); }
      });
    } catch (cause) { rememberFailure(cause); }
    finally { licenseBusy = false; }
  }
  // Disabled/development distributions incur no additional network or native reads.
  const licenseTimer = licensing.status().mode === 'required' && options.licenseIntervalMs !== 0
    ? setInterval(() => { void enforceLicense(); }, options.licenseIntervalMs || 5000) : null;
  licenseTimer?.unref();
  server.enforceLicense = enforceLicense;
  server.isConnecting = () => Boolean(connectionAttempt);
  server.once('close', () => { clearInterval(licenseTimer); licensing.close?.(); });
  server.once('close', () => clearInterval(healthTimer));
  server.once('close', () => { void applicationGateway.stop().catch(() => {}); });
  server.once('close', () => { if (!closing) void browserObservation.close().catch(() => {}); });
  return server;
}

export async function startController(options = {}) {
  const host = options.host || '127.0.0.1';
  if (host !== '127.0.0.1') throw error('HOST_INVALID', '控制服务只允许绑定 127.0.0.1', 400);
  const port = options.port ?? 17654;
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw error('PORT_INVALID', '控制端口无效', 400);
  const server = createControllerServer(options);
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); });
  try { await server.initializeLicense(); await server.initialize(); }
  catch (cause) {
    await new Promise(resolve => server.close(resolve));
    await server.runtime.dispose?.();
    throw cause;
  }
  return server;
}
