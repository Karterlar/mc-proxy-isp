export const PRODUCT_NAME = 'MC Proxy';
export const EXTERNAL_LINKS = new Set(['https://cleanip.io/claude', 'https://ippure.com/claude', 'https://ping0.cc/', 'https://claude.ai/', 'https://www.tiktok.com/']);

export const WINDOW_LAYOUTS = Object.freeze({ wide: Object.freeze({width:1080,height:760}), standard: Object.freeze({width:900,height:800}), tall: Object.freeze({width:480,height:800}) });
export function fitWindow(workArea = { x: 0, y: 0, width: 1280, height: 960 }, preferred = {width:1080,height:800}) {
  const valid = Number.isInteger(preferred?.width)&&Number.isInteger(preferred?.height)&&preferred.width>=380&&preferred.width<=4096&&preferred.height>=650&&preferred.height<=2160;
  const size = valid ? preferred : {width:1080,height:800};
  const width = Math.max(1, Math.min(size.width, workArea.width - Math.min(24, Math.floor(workArea.width / 10))));
  const height = Math.max(1, Math.min(size.height, workArea.height - Math.min(24, Math.floor(workArea.height / 10))));
  return {
    width, height,
    minWidth: Math.min(380, width), minHeight: Math.min(650, height),
    x: workArea.x + Math.round((workArea.width - width) / 2),
    y: workArea.y + Math.round((workArea.height - height) / 2),
  };
}

export function parseLaunchOptions(argv, { root, userData, packaged = false, env = {} }) {
  const values = new Map();
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (['--runtime-root', '--config-path', '--secrets-path', '--core-path', '--control-port', '--capture-dir'].includes(arg)) {
      if (!argv[index + 1] || argv[index + 1].startsWith('--')) throw new Error(`${arg} requires a value`);
      values.set(arg, argv[++index]);
    }
  }
  const mock = argv.includes('--mock') || env.PROXYPILOT_MOCK === '1';
  const smoke = argv.includes('--smoke-test');
  if (smoke && !mock) throw new Error('Desktop acceptance must use --mock');
  const port = Number(values.get('--control-port') ?? env.PROXYPILOT_CONTROL_PORT ?? 0);
  if (!Number.isInteger(port) || port < 0 || port > 65535 || (port > 0 && port < 1024)) throw new Error('Control port must be 0 or between 1024 and 65535');
  return {
    mock, smoke, port,
    runtimeRoot: values.get('--runtime-root') || (!mock && env.MC_PROXY_RUNTIME_ROOT) || `${packaged ? userData : root}/${mock ? '.cache/desktop-mock/runtime' : packaged ? 'runtime' : 'backend/runtime'}`,
    configPath: values.get('--config-path') || (!mock && env.PROXYPILOT_CONFIG_PATH) || undefined,
    secretsPath: values.get('--secrets-path') || (!mock && env.PROXYPILOT_SECRETS_PATH) || undefined,
    corePath: values.get('--core-path') || env.PROXYPILOT_CORE_PATH || undefined,
    captureDir: values.get('--capture-dir') || `${packaged ? userData : root}/.cache/desktop-acceptance`,
  };
}

export function classifyNavigation(value, origin) {
  try {
    const url = new URL(value);
    if (url.username || url.password) return 'blocked';
    if (url.origin === origin && ['/', '/index.html'].includes(url.pathname) && !url.search) return 'app';
    if (url.origin === origin && /^\/reports\/quality\/[a-f0-9-]{36}\/(cleanip|ippure|ping0)$/.test(url.pathname) && !url.search && !url.hash) return 'report';
    if (EXTERNAL_LINKS.has(url.href)) return 'external';
  } catch {}
  return 'blocked';
}

export function trustedSender(event, webContents, origin) {
  try { return Boolean(event && webContents && !webContents.isDestroyed?.() && event.sender === webContents && event.senderFrame === webContents.mainFrame && classifyNavigation(event.senderFrame?.url, origin) === 'app'); }
  catch { return false; }
}

export function controllerRequestHeaders(details, { webContents, origin, headers } = {}) {
  const result = Object.fromEntries(Object.entries(details.requestHeaders || {}).filter(([name]) => name.toLowerCase() !== 'x-mc-control-token'));
  try {
    const target = new URL(details.url);
    if (webContents && !webContents.isDestroyed?.() && details.webContentsId === webContents.id
      && details.frame === webContents.mainFrame && classifyNavigation(details.frame.url, origin) === 'app'
      && (!details.initiatorOrigin || details.initiatorOrigin === origin)
      && target.origin === origin && target.pathname.startsWith('/api/') && !target.username && !target.password) Object.assign(result, headers);
  } catch {}
  return result;
}

export function desktopError(cause) {
  const messages = {
    DESKTOP_BUSY: '请等待当前操作完成后再操作。',
    DESKTOP_IPC_INVALID: '桌面操作参数无效。',
    DESKTOP_IPC_UNTRUSTED: '此页面不能调用桌面操作，请重新打开主窗口。',
    DESKTOP_LOG_UNAVAILABLE: '无法打开客户端日志，请在本机用户数据目录查看 desktop.log。',
    CLAUDE_BACKGROUND_CHECK_FAILED: '暂时无法核实 Claude 后台服务，请在 Windows 服务管理中查看；未修改任何服务。',
    CLAUDE_BACKGROUND_PLATFORM_UNSUPPORTED: 'Claude 后台服务管理目前仅支持 Windows。',
    CLAUDE_SERVICES_OPEN_FAILED: '无法打开 Windows 服务管理，请按 Win＋R 输入 services.msc；未修改任何服务。',
    CLAUDE_BACKGROUND_BUSY: 'Claude 后台服务操作正在进行，请等待结果。',
    CLAUDE_STARTUP_ADMIN_REQUIRED: '需要以管理员身份打开 MC Proxy 才能修改 Claude 后台服务的开机设置；未执行修改。',
    CLAUDE_STARTUP_IDENTITY_UNVERIFIED: '尚未核实这是官方 Claude 后台服务，未修改开机设置。请在 Windows 服务管理中查看。',
    CLAUDE_STARTUP_ACCESS_DENIED: 'Windows 拒绝修改 Claude 的受保护服务，无法确认禁止开机自启。没有修改系统权限或绕过保护。',
    CLAUDE_STARTUP_CONFLICT: 'Claude 服务、原设置或恢复记录已变化，未继续修改。请在 Windows 服务管理中核对；不会覆盖其他软件的设置。',
    CLAUDE_STARTUP_UNCONFIRMED: '尚未确认 Claude 后台服务的开机设置已完整修改或恢复，请在 Windows 服务管理中查看；恢复记录已保留。',
    CLAUDE_STARTUP_RECORD_FAILED: '无法安全保存或读取 Claude 开机设置的恢复记录，请检查本机文件权限；未继续修改。',
    CLAUDE_STARTUP_REGISTRY_UNREADABLE: '无法核实 Claude 服务的原始启动值或延迟启动设置，未执行修改。请在 Windows 服务管理中核对。',
    APPLICATION_TARGET_INVALID: '应用启动目标无效。',
    APPLICATION_PROXY_INVALID: '本地代理地址无效，应用未启动。',
    APPLICATION_PROXY_UNVERIFIED: '代理出口尚未通过核验，应用未启动。',
    APPLICATION_NOT_INSTALLED: '未找到此应用的可执行程序，请安装后刷新列表。',
    APPLICATION_RESTART_REQUIRED: '桌面应用正在运行。请自行完整退出后再从这里启动；已有进程不能继承新代理设置。也可使用已核验的全局 TUN。',
    APPLICATION_PROCESS_STATE_UNKNOWN: '无法确认桌面应用是否仍在运行，请自行检查并完整退出后刷新列表。未启动新进程。',
    APPLICATION_BINARY_CHANGED: '应用程序已变化，请刷新列表后重试。',
    APPLICATION_LAUNCH_FAILED: '应用未能启动，请检查安装与运行权限。',
    APPLICATION_LAUNCH_TIMEOUT: '尚未确认应用启动，请检查是否已有窗口，再刷新列表。',
    APPLICATION_PLATFORM_UNSUPPORTED: '应用启动入口目前仅支持 Windows。',
    APPLICATION_SYSTEM_PROTECTION_REQUIRED: '网页登录会打开系统默认浏览器。请先连接全局 TUN 并核验当前出口，再启动应用；断网锁为可选功能。',
    APPLICATION_CLOSE_MANUALLY: '此终端没有可核验的受管退出身份。请在原终端结束任务并关闭窗口，再刷新列表。',
    APPLICATION_STOP_UNCONFIRMED: '尚未确认应用完整退出。请检查未保存内容或托盘进程，再刷新列表；没有强制结束。',
    APPLICATION_STOP_FAILED: '未能正常关闭此应用。请自行退出后刷新列表；没有强制结束。',
    APPLICATION_NOT_RUNNING: '未发现可安全退出的应用进程，请刷新列表。',
    APPLICATION_PROCESS_IDENTITY_CHANGED: '应用进程身份已改变，未继续退出操作。请重新识别或自行退出。',
    APPLICATION_CLOSE_TIMEOUT: '应用尚未完整退出，请处理未保存内容或托盘进程后重试；没有强制结束。',
    APPLICATION_CLOSE_FAILED: '应用没有接受正常关闭请求，请自行退出后重新识别；没有强制结束。',
    APPLICATION_TARGET_UNREACHABLE: '应用目标服务尚未通过代理链路核验。请在应用接入页检查目标服务，再启动；不会改用直连。',
    SERVICE_STOPPING: '控制服务正在安全关闭，请等待完成。',
    SERVICE_REPAIRING: '网络修复正在进行，请等待结果。',
    EXIT_UNVERIFIED: '代理出口尚未通过核验，应用未启动。',
    LICENSE_ADMIN_UNAVAILABLE: '客户签发工具仅在开发者版提供。',
    LICENSE_ADMIN_MOCK_UNAVAILABLE: '演示模式不读取签发私钥，也不生成真实许可。',
    LICENSE_ADMIN_BUSY: '签发工具正在处理操作，请等待完成。',
    LICENSE_ADMIN_ARGUMENT_INVALID: '请检查操作、客户编号、订单号和有效期。',
    LICENSE_ADMIN_APPLICATION_INVALID: '请粘贴客户完整的设备申请 JSON；申请不可编辑或截断。',
    LICENSE_ADMIN_STORE_REQUIRED: '请先选择已发布安装包对应的私有签发库。',
    LICENSE_ADMIN_STORE_CHANGED: '签发库的公钥已变化，请核对后重新选择。',
    LICENSE_ADMIN_SETTINGS_INVALID: '签发库选择记录无法读取，请保留原库并检查文件权限。',
    LICENSE_ADMIN_OUTPUT_INVALID: '请选择新的 .json 许可文件名。',
    DELIVERY_INVALID: '交付文件格式无效，请检查客户 VPN 与 ISP 信息。',
    DELIVERY_ISP_INVALID: 'ISP 地址、端口或凭据无效，请检查填写内容。',
    DELIVERY_VPN_INVALID: 'VPN 配置无效或没有支持的节点。',
    DELIVERY_SIZE_INVALID: '交付文件过大，请精简 VPN 配置后重试。',
    DELIVERY_LICENSE_INVALID: '请选择当前客户原始、完整的签名许可。',
    DELIVERY_LICENSE_INACTIVE: '此许可已到期或不可用，请先按原流程为客户生成有效许可。',
    DELIVERY_LICENSE_MISMATCH: '此许可与当前签发库或客户记录不一致，请重新核对。',
    DELIVERY_LICENSE_STALE: '此许可不是客户当前有效版本，请先按原流程重新签发后制作交付。',
    DELIVERY_LICENSE_INPUT_REQUIRED: '请通过客户许可文件选择窗口制作交付。',
    DELIVERY_MODE_INVALID: '交付模式与包含的配置不一致，请重新检查。',
    SUPPORT_OUTPUT_INVALID: '请使用 .json 文件名保存故障报告。',
    SUPPORT_OUTPUT_EXISTS: '同名文件已存在，请选择新文件名保留原报告。',
    SUPPORT_OUTPUT_FAILED: '报告未能保存，请选择可写入的文件夹重试。',
    PAYMENT_NOT_CONFIRMED: '请先确认已收到本次100元订单款项，再签发正式授权。',
    RESOURCE_NOT_READY: '包含 ISP 的套餐须确认独立 ISP 可用并填写真实到期时间；客户自备 ISP 无需供应商日期，免费可选 VPS 不限制授权。',
    RESOURCE_TERM_TOO_SHORT: '套餐 ISP 必须完整覆盖本次软件授权截止；免费可选 VPS 不限制期限。请先延长 ISP；本次未新增收款记录、未延期、未保存许可。',
    INVALID_RESOURCE_MODE: '请选择包含 ISP 或客户自带 ISP 的资源供应方式。',
    CARD_RESOURCE_MODE_FIXED: '未兑换卡密须按原付款订单的 ISP 供应方式更新资源，不能修改历史成本。',
    TRIAL_ALREADY_ISSUED: '此设备已经领取试用，请选择原客户转正式或处理原许可。',
    TRIAL_UNAVAILABLE: '此设备已有正式授权，不能降级领取试用。',
    INVALID_TRIAL: '试用不登记收款订单，请使用“1天试用”操作。',
    TRIAL_WINDOW_FIXED: '试用许可固定为1天，满意后再转30天正式授权。',
    ORDER_CONFLICT: '此订单号属于另一笔操作或客户，请核对原订单后重试。',
    INVALID_ARGUMENT: '签发参数不完整或不合法，请检查客户、日期与确认选项。',
    INVALID_OFFLINE_WINDOW: '请选择1、3、7、15或30天离线许可。',
    LICENSE_REVOKED: '该许可已撤销，不能直接续费；请核对客户与设备。',
    LICENSE_NOT_FOUND: '未找到客户许可，请刷新客户列表后选择。',
    LICENSE_EXPIRED: '软件或离线授权窗口已到期；免费重签不会延长软件付费期。请核对原许可后重签或续费，旧 v1 许可另受原资源期限限制。',
    ORDER_EXISTS: '此订单号已记录，请核对原订单，避免重复收款或签发。',
    OUTPUT_EXISTS: '所选文件已存在，请换一个新文件名；原文件已保留。',
    UNSAFE_FILE: '签发库或许可路径不是普通文件，请检查链接、权限和路径。',
    INVALID_SERVER_CONFIG: '所选目录不是有效签发库，请选择包含原 server-config.json 的私有目录。',
    SIGNING_KEY_UNAVAILABLE: '无法读取所选签发库的私钥，请核对原库及备份。',
    SERVER_CLOCK_INVALID: '管理员电脑的时间早于原台账记录，请校准时间后重试。',
  };
  const code = typeof cause?.code === 'string' && /^[A-Z][A-Z0-9_]{0,79}$/.test(cause.code) ? cause.code : 'DESKTOP_ACTION_FAILED';
  return { code, message: Object.hasOwn(messages, code) ? messages[code] : '桌面操作未完成，请查看主窗口状态与诊断记录。' };
}

export function exitNotice({ proxy = {}, browser = {}, networkLock = {}, operation = null } = {}) {
  if (operation) return { blocked: true, message: 'MC Proxy 正在执行操作，请等待完成后再退出。' };
  const active = proxy.running || browser.running;
  const locked = networkLock.locked || (networkLock.state && networkLock.state !== 'unlocked' && networkLock.state !== 'unavailable');
  return {
    blocked: false,
    requiresConfirmation: Boolean(active || locked),
    message: active ? '退出将结束代理与独立浏览器会话。' : '是否退出 MC Proxy？',
    detail: locked ? (networkLock.locked || networkLock.state === 'locked' ? '断网锁仍将保持，网络可能继续被阻断。重新打开 MC Proxy 后，可在确认安全的情况下手动解除。退出不会自动恢复直连。' : '网络保护或恢复状态尚未确认。请保留恢复记录，重新打开 MC Proxy 检查。退出不会自动恢复直连，也不会自动清除恢复记录。') : '关闭按钮只会将窗口收起到系统托盘；从托盘可随时重新打开。',
  };
}
