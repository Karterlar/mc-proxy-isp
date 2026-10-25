const PRESETS = Object.freeze({
  wide: { label: '横向布局', short: '横向', width: 1080, height: 760 },
  standard: { label: '标准布局', short: '标准', width: 900, height: 800 },
  tall: { label: '纵向布局', short: '纵向', width: 480, height: 800 },
});

// Window sizing is owned by the desktop host; this menu never changes page order.
export function initLayoutPreferences({ canEdit = () => true } = {}) {
  const button = document.getElementById('layoutButton');
  const menu = document.getElementById('layoutMenu');
  const status = document.getElementById('windowLayoutStatus');
  const current = document.getElementById('windowLayoutCurrent');
  const closeButton = document.getElementById('layoutCloseButton');
  if (!button || !menu || !status || !closeButton) return { refresh() {}, destroy() {} };

  const options = [...menu.querySelectorAll('button[data-layout-preset]')];
  const native = typeof window.mcDesktop?.setWindowLayout === 'function';
  let busy = false;
  let disposed = false;
  let revision = 0;
  let currentPreset = null;
  let resizeTimer;

  function editable() {
    try { return canEdit() === true; } catch { return false; }
  }

  function renderChoice() {
    options.forEach(option => {
      const selected = option.dataset.layoutPreset === currentPreset;
      option.setAttribute('aria-pressed', String(selected));
      const marker = option.querySelector('.window-layout-selected');
      if (marker) marker.hidden = !selected;
    });
    const choice = PRESETS[currentPreset];
    if (current) current.textContent = choice?.short || '自定';
    const label = `窗口布局，当前：${choice?.label || '自定尺寸'}`;
    button.setAttribute('aria-label', label);
    button.title = label;
  }

  function refresh() {
    button.disabled = !editable();
    options.forEach(option => { option.disabled = !native || busy || !editable(); });
    menu.setAttribute('aria-busy', String(busy));
    if (!native) status.textContent = '桌面版支持窗口比例；浏览器请拖动窗口边缘调整大小。';
  }

  function showBounds(layout) {
    if (!layout || !layout.bounds) return;
    const { width, height } = layout.bounds;
    if (!Number.isInteger(width) || !Number.isInteger(height) || width < 1 || height < 1 || width > 20000 || height > 20000) return;
    currentPreset = Object.hasOwn(PRESETS, layout.preset) ? layout.preset : null;
    renderChoice();
    const name = currentPreset ? PRESETS[currentPreset].label : '自定尺寸';
    status.textContent = `${name} · ${width} × ${height}${layout.clamped ? '，已适配当前屏幕可用区域' : ''}。可拖动窗口边缘继续调整。`;
  }

  async function readCurrent() {
    if (disposed || busy || !native || typeof window.mcDesktop?.getInfo !== 'function') return;
    const reading = revision;
    try {
      const info = await window.mcDesktop.getInfo();
      if (!disposed && !busy && reading === revision) showBounds(info?.windowLayout);
    } catch {
      if (!disposed && !busy && reading === revision && !menu.hidden) status.textContent = '暂时无法读取当前尺寸，可选择预设或拖动窗口边缘。';
    }
  }

  function resized() {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(readCurrent, 250);
  }

  function close({ restoreFocus = true } = {}) {
    if (menu.hidden) return;
    menu.hidden = true;
    button.setAttribute('aria-expanded', 'false');
    revision++;
    if (restoreFocus && !button.disabled) button.focus({ preventScroll: true });
  }

  async function open() {
    if (busy || !editable()) return;
    if (!menu.hidden) { close(); return; }
    menu.hidden = false;
    button.setAttribute('aria-expanded', 'true');
    refresh();
    closeButton.focus({ preventScroll: true });
    revision++;
    await readCurrent();
  }

  async function choose(event) {
    const option = event.target.closest?.('button[data-layout-preset]');
    if (!options.includes(option) || !Object.hasOwn(PRESETS, option.dataset.layoutPreset)) return;
    if (!native || busy || !editable()) { renderChoice(); return; }
    const preset = option.dataset.layoutPreset;
    const requested = ++revision;
    const focused = document.activeElement === option;
    busy = true;
    status.textContent = '正在调整窗口尺寸…';
    refresh();
    if (focused) closeButton.focus({ preventScroll: true });
    try {
      const result = await window.mcDesktop.setWindowLayout(preset);
      if (disposed) return;
      if (!result || result.preset !== preset || !result.bounds || ![result.bounds.width, result.bounds.height].every(value => Number.isInteger(value) && value >= 1 && value <= 20000)) {
        throw new Error('Invalid window layout response');
      }
      currentPreset = preset;
      renderChoice();
      if (requested === revision) showBounds(result);
    } catch {
      if (!disposed) {
        renderChoice();
        if (requested === revision) status.textContent = '窗口尺寸未调整，请重试。';
      }
    } finally {
      busy = false;
      if (!disposed) {
        refresh();
        if (!menu.hidden && focused && document.activeElement === closeButton && !option.disabled) option.focus({ preventScroll: true });
      }
    }
  }

  function outside(event) {
    if (!menu.hidden && !menu.contains(event.target) && !button.contains(event.target)) close({ restoreFocus: false });
  }
  function escape(event) {
    if (!menu.hidden && event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); close(); }
  }
  function focusOut() {
    requestAnimationFrame(() => {
      if (!disposed && !busy && !menu.hidden && !menu.contains(document.activeElement) && document.activeElement !== button) close({ restoreFocus: false });
    });
  }
  const onClose = () => close();
  button.addEventListener('click', open);
  closeButton.addEventListener('click', onClose);
  menu.addEventListener('click', choose);
  menu.addEventListener('focusout', focusOut);
  document.addEventListener('pointerdown', outside);
  document.addEventListener('keydown', escape, true);
  window.addEventListener('resize', resized);
  renderChoice();
  refresh();
  void readCurrent();

  return {
    refresh,
    destroy() {
      disposed = true;
      clearTimeout(resizeTimer);
      close({ restoreFocus: false });
      button.removeEventListener('click', open);
      closeButton.removeEventListener('click', onClose);
      menu.removeEventListener('click', choose);
      menu.removeEventListener('focusout', focusOut);
      document.removeEventListener('pointerdown', outside);
      document.removeEventListener('keydown', escape, true);
      window.removeEventListener('resize', resized);
    },
  };
}
