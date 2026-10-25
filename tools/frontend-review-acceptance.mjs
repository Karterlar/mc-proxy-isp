// Browser-side assertions shared by the loopback-only UI acceptance harness.
// These checks never launch applications, access user profiles, or change Windows.
export async function auditRouteVisibility(page, check, label) {
  const result = await page.evaluate(async () => {
    const positions = [...document.querySelectorAll('*')].filter(node => node.scrollHeight > node.clientHeight || node.scrollWidth > node.clientWidth).map(node => [node, node.scrollTop, node.scrollLeft]);
    const nodes = [...document.querySelectorAll('#connectionChain .route-node')];
    const visibleFraction = element => {
      const box = element.getBoundingClientRect();
      let left = Math.max(0, box.left), top = Math.max(0, box.top), right = Math.min(innerWidth, box.right), bottom = Math.min(innerHeight, box.bottom);
      for (let parent = element.parentElement; parent; parent = parent.parentElement) {
        const style = getComputedStyle(parent), clip = parent.getBoundingClientRect();
        if (/auto|scroll|hidden|clip/.test(style.overflowX)) { left = Math.max(left, clip.left); right = Math.min(right, clip.right); }
        if (/auto|scroll|hidden|clip/.test(style.overflowY)) { top = Math.max(top, clip.top); bottom = Math.min(bottom, clip.bottom); }
      }
      return box.width > 0 && box.height > 0 ? Math.max(0, right - left) * Math.max(0, bottom - top) / (box.width * box.height) : 0;
    };
    const result = [];
    for (const node of nodes) {
      const initial = visibleFraction(node);
      node.scrollIntoView({ block: 'nearest', inline: 'nearest', behavior: 'instant' });
      await new Promise(resolve => requestAnimationFrame(resolve));
      result.push({ text: node.textContent.trim(), initial, reachable: visibleFraction(node) });
    }
    const actions = [];
    for (const selector of ['#connectButton', '#returnPreferencesButton', '#editIspButton']) {
      const node = document.querySelector(selector);
      node.scrollIntoView({ block: 'nearest', inline: 'nearest', behavior: 'instant' });
      await new Promise(resolve => requestAnimationFrame(resolve));
      actions.push({ selector, reachable: visibleFraction(node) });
    }
    for (const [node, top, left] of positions) node.scrollTo({ top, left, behavior: 'instant' });
    return { nodes: result, actions };
  });
  check(`${label}: all four route labels are readable or fully scroll-reachable`, result.nodes.length === 4 && result.nodes.every(item => item.reachable >= .98), result.nodes);
  check(`${label}: connection and preparation actions remain fully scroll-reachable`, result.actions.every(item => item.reachable >= .98), result.actions);
}

export async function auditStableNodes(page, check, label, selectors, { focus } = {}) {
  if (focus) await page.locator(focus).first().focus();
  await page.evaluate(selectors => {
    window.mcReviewStableNodes = selectors.map(selector => ({ selector, nodes: [...document.querySelectorAll(selector)] }));
    window.mcReviewFocus = document.activeElement;
  }, selectors);
  await page.waitForTimeout(2300);
  // Exercise a same-state service refresh too, without stealing the user's focus.
  const refresh = page.waitForResponse(response => new URL(response.url()).pathname === '/api/status' && response.request().method() === 'GET');
  await page.locator('#refreshButton').evaluate(button => button.click());
  await (await refresh).finished();
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  const result = await page.evaluate(() => ({
    nodes: window.mcReviewStableNodes.map(({ selector, nodes }) => ({ selector, count: nodes.length, preserved: nodes.length > 0 && nodes.length === document.querySelectorAll(selector).length && nodes.every((node, index) => node === document.querySelectorAll(selector)[index] && node.isConnected) })),
    focusPreserved: document.activeElement === window.mcReviewFocus,
  }));
  check(`${label}: idle and same-state service refresh preserve existing controls and option nodes`, result.nodes.every(item => item.preserved), result.nodes);
  if (focus) check(`${label}: idle refresh preserves keyboard focus`, result.focusPreserved);
}

export async function auditIdleMutations(page, check, label) {
  const collect = async hidden => page.evaluate(async hidden => {
    if (hidden) Object.defineProperty(document, 'hidden', { configurable: true, value: true });
    const liveNodes = [...document.querySelectorAll('[role="status"],[role="alert"],[aria-live]')];
    const originals = new Map(liveNodes.map(node => [node, node.textContent]));
    let writes = 0, unchanged = 0;
    const observer = new MutationObserver(records => {
      for (const record of records) {
        const target = record.target.nodeType === Node.ELEMENT_NODE ? record.target : record.target.parentElement;
        const region = target?.closest('[role="status"],[role="alert"],[aria-live]');
        if (region && originals.has(region)) { writes++; if (originals.get(region) === region.textContent) unchanged++; originals.set(region, region.textContent); }
      }
    });
    observer.observe(document.body, { childList: true, characterData: true, subtree: true });
    await new Promise(resolve => setTimeout(resolve, 2300));
    observer.disconnect();
    if (hidden) { delete document.hidden; document.dispatchEvent(new Event('visibilitychange')); }
    return { writes, unchanged, emulatedHidden: hidden };
  }, hidden);
  const visible = await collect(false), hidden = await collect(true);
  check(`${label}: identical live-region text is not rewritten while idle`, visible.unchanged === 0, visible);
  check(`${label}: hidden document skips repeated presentation writes`, hidden.unchanged === 0 && hidden.writes === 0, hidden);
}

export async function auditDrawerError(page, check, label, expectedText) {
  await page.locator('#drawerErrorNotice').waitFor({ state: 'visible' });
  const result = await page.evaluate(() => {
    const error = document.querySelector('#drawerErrorNotice');
    const box = error.getBoundingClientRect(), hit = document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2);
    const alerts = [...document.querySelectorAll('[role="alert"]')].filter(node => node.getClientRects().length && getComputedStyle(node).visibility !== 'hidden');
    return { text: error.textContent, foreground: hit === error || error.contains(hit), alerts: alerts.map(node => node.id), alertInDrawer: alerts.length === 1 && (alerts[0] === error || error.contains(alerts[0])), duplicateToasts: [...document.querySelectorAll('#toastStack .toast')].filter(node => node.textContent && error.textContent.includes(node.textContent)).length };
  });
  check(`${label}: drawer failure has one foreground alert and no duplicate toast`, expectedText.test(result.text) && result.foreground && result.alertInDrawer && result.duplicateToasts === 0, result);
  await page.locator('#dismissDrawerErrorButton').click();
  check(`${label}: resolved operation error can be dismissed without closing its drawer`, await page.locator('#drawerErrorNotice').isHidden() && await page.locator('#errorNotice').isHidden() && await page.locator('#drawerBackdrop').isVisible());
}
