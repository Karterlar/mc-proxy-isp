// Compare the last template, not serialized DOM: icon hydration may change it.
const htmlTemplates = new WeakMap();

export function setText(element, value) {
  const text = String(value ?? '');
  if (element.textContent === text) return false;
  element.textContent = text;
  return true;
}

export function setHtml(element, value) {
  const html = String(value ?? '');
  if (htmlTemplates.get(element) === html) return false;
  element.innerHTML = html;
  htmlTemplates.set(element, html);
  return true;
}
