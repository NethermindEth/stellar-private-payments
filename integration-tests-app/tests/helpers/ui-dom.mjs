// Minimal DOM for UI lifecycle tests. Native keyboard activation and layout are
// covered separately in Chrome, rather than simulated by this tree.
export class Element {
  constructor(tag = 'div', attrs = {}) {
    this.tagName = tag.toUpperCase();
    this.dataset = {};
    this.children = [];
    this.attributes = new Map();
    this.listeners = {};
    this.style = {};
    this.hidden = false;
    this.className = '';
    this.textContent = '';
    Object.assign(this, attrs);
    this.classList = {
      toggle: (name, force) => {
        const classes = new Set(this.className.split(' ').filter(Boolean));
        const add = force ?? !classes.has(name);
        if (add) classes.add(name); else classes.delete(name);
        this.className = [...classes].join(' ');
      },
      add: (...names) => names.forEach(name => this.classList.toggle(name, true)),
      remove: (...names) => names.forEach(name => this.classList.toggle(name, false)),
    };
  }
  get isConnected() { return this === document.body || document.body.contains(this); }
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  getAttribute(name) { return this.attributes.get(name) ?? null; }
  removeAttribute(name) { this.attributes.delete(name); }
  append(...nodes) { nodes.forEach(node => this.insertBefore(node, null)); }
  appendChild(node) { this.append(node); return node; }
  insertBefore(node, before) {
    node.remove();
    this.children.splice(before ? this.children.indexOf(before) : this.children.length, 0, node);
    node.parent = this;
  }
  after(node) {
    const index = this.parent.children.indexOf(this);
    this.parent.insertBefore(node, this.parent.children[index + 1] ?? null);
  }
  remove() {
    if (!this.parent) return;
    if (this.contains(document.activeElement)) document.activeElement = document.body;
    this.parent.children.splice(this.parent.children.indexOf(this), 1);
    this.parent = null;
  }
  replaceChildren(...nodes) { [...this.children].forEach(node => node.remove()); this.append(...nodes); }
  contains(node) { for (let n = node; n; n = n.parent) if (n === this) return true; return false; }
  matches(selector) {
    if (selector.startsWith('#')) return this.id === selector.slice(1);
    if (selector.startsWith('.')) return this.className.split(' ').includes(selector.slice(1));
    if (selector.startsWith('[')) {
      const [, name, value] = selector.match(/^\[data-([\w-]+)(?:="([^"]*)")?\]$/) ?? [];
      const key = name?.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
      return key in this.dataset && (value === undefined || this.dataset[key] === value);
    }
    return this.tagName === selector.toUpperCase();
  }
  querySelectorAll(selector) {
    return this.children.flatMap(child => [
      ...(selector.split(',').some(part => child.matches(part.trim())) ? [child] : []),
      ...child.querySelectorAll(selector),
    ]);
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] ?? null; }
  addEventListener(type, listener) { (this.listeners[type] ??= []).push(listener); }
  dispatch(type, init = {}) {
    const event = { target: this, preventDefault() { this.defaultPrevented = true; }, ...init };
    for (let node = this; node; node = node.parent) (node.listeners[type] ?? []).forEach(listener => listener(event));
    if (this !== document) (document.listeners[type] ?? []).forEach(listener => listener(event));
    return event;
  }
  click() { this.dispatch('click'); }
  focus() { document.activeElement = this; }
  showPopover() {}
  hidePopover() {}
  getBoundingClientRect() {
    return this.rect ?? { left: 0, top: 0, right: parseFloat(this.style.width) || 352, bottom: 0, height: Math.min(400, parseFloat(this.style.maxHeight) || 400) };
  }
}

export function installDom() {
  const doc = new Element('document');
  doc.body = new Element('body');
  doc.activeElement = doc.body;
  doc.createElement = tag => new Element(tag);
  doc.getElementById = id => doc.body.querySelector(`#${id}`);
  doc.querySelectorAll = selector => doc.body.querySelectorAll(selector);
  doc.querySelector = selector => doc.body.querySelector(selector);
  globalThis.document = doc;
  const win = new Element('window');
  Object.assign(win, {
    innerWidth: 1024, innerHeight: 768,
    location: { hash: '' }, history: { replaceState(_, __, hash) { win.location.hash = hash; } },
  });
  globalThis.window = win;
  return { document: doc, window: win };
}

export function balanceCard() {
  const card = new Element('article');
  for (const name of ['token', 'pool', 'amount']) card.append(new Element('a', { className: `balance-${name}` }));
  card.append(new Element('button', { className: 'balance-notes', dataset: { viewNotes: '' } }));
  card.append(new Element('button', { dataset: { overviewPoolControls: '' }, rect: { left: 200, right: 244, top: 100, bottom: 144, width: 44, height: 44 } }));
  for (const quickFlow of ['deposit', 'transfer', 'withdraw']) card.append(new Element('button', { dataset: { quickFlow } }));
  card.append(new Element('button', { dataset: { viewHistory: '' } }));
  return card;
}
