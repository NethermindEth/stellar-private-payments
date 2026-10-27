/**
 * The "Pool controls" sections under the Available Token pickers: one tag per
 * control of the selected pool, in `poolControls` order, each a button that
 * opens its explanation below the tags. Hover or keyboard focus previews the
 * explanation; clicking pins it open until clicked again or dismissed.
 *
 * Each section is a `[data-pool-controls]` element whose value scopes its
 * panel ids. A section keeps at most one explanation open; Escape closes it.
 * Selecting another pool rebuilds the tags, which closes it too, while a
 * refresh that leaves the pool and its controls as they were keeps it open.
 *
 * @module ui/pool-controls
 */

import { POOL_CONTROLS, poolControls } from '../pool-policy.js';
import { App, Utils } from './core.js';
import { el, svgEl } from './dom.js';

const TAG = 'inline-flex min-h-11 items-center gap-2 rounded-full border px-3.5 text-[13px] font-semibold transition focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-300/60 aria-expanded:ring-2';
const PANEL = 'rounded-xl border border-white/10 bg-ink-850 p-3 text-sm leading-relaxed';

// Open is the absence of ASP checks, so it stays neutral; ASP lists are cyan
// and the admin view key is violet. Amber is reserved for warnings.
const NEUTRAL = { tag: 'border-white/10 bg-white/[0.04] text-slate-200 aria-expanded:ring-slate-300/30', impact: 'text-slate-300' };
const ASP = { tag: 'border-cyan-300/30 bg-cyan-400/10 text-cyan-100 aria-expanded:ring-cyan-300/30', impact: 'text-cyan-200' };
const VIEW_KEY = { tag: 'border-violet-300/30 bg-violet-300/10 text-violet-200 aria-expanded:ring-violet-300/30', impact: 'text-violet-200' };
const TONES = { open: NEUTRAL, allowlist: ASP, blocklist: ASP, viewOnly: VIEW_KEY, traceable: VIEW_KEY };

function helpIcon() {
    return svgEl('svg', { class: 'h-3.5 w-3.5 shrink-0', viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '1.8', 'aria-hidden': 'true' }, [
        svgEl('circle', { cx: '12', cy: '12', r: '9' }),
        svgEl('path', { d: 'M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .9-1 1.6v.6', 'stroke-linecap': 'round' }),
        svgEl('circle', { cx: '12', cy: '17', r: '0.9', fill: 'currentColor', stroke: 'none' }),
    ]);
}

function sections() {
    return [...document.querySelectorAll('[data-pool-controls]')].map((root) => ({
        root,
        scope: root.dataset.poolControls,
        tags: root.querySelector('[data-pool-controls-tags]'),
        panels: root.querySelector('[data-pool-controls-panels]'),
    }));
}

// Tags and panels are built in the same order, so the nth panel explains the
// nth tag.
function entries(section) {
    const panels = [...section.panels.children];
    return [...section.tags.children].map((button, index) => ({ button, panel: panels[index] }));
}

function show(section, open) {
    for (const { button, panel } of entries(section)) {
        const expanded = button === open;
        button.setAttribute('aria-expanded', String(expanded));
        panel.hidden = !expanded;
    }
}

function build(section, control) {
    const { tag, explanation, impact } = POOL_CONTROLS[control];
    const tone = TONES[control];
    const panelId = `${section.scope}-pool-control-${control}`;

    const button = el('button', `${TAG} ${tone.tag}`);
    button.type = 'button';
    button.dataset.poolControl = control;
    button.setAttribute('aria-expanded', 'false');
    button.setAttribute('aria-controls', panelId);
    button.append(el('span', '', tag), helpIcon());
    button.addEventListener('pointerenter', (event) => {
        if (event.pointerType !== 'mouse' && event.pointerType !== 'pen') return;
        if (section.pinned && section.pinned !== button) section.pinned = null;
        show(section, button);
    });
    button.addEventListener('focus', () => show(section, button));
    button.addEventListener('click', () => {
        section.pinned = section.pinned === button ? null : button;
        show(section, section.pinned);
    });

    const panel = el('div', PANEL);
    panel.id = panelId;
    panel.hidden = true;
    panel.append(
        el('p', 'font-semibold text-white', tag),
        el('p', 'mt-1 text-slate-300', explanation),
        el('p', `mt-2 text-xs ${tone.impact}`, impact),
    );
    return { button, panel };
}

function render(section) {
    const { root, tags, panels } = section;
    if (!tags || !panels) return;
    const pool = Utils.selectedPool();
    const controls = pool ? poolControls(pool) : [];
    root.hidden = !pool;
    const shown = pool ? `${pool.poolContractId}|${controls.join(',')}` : '';
    if (root.dataset.shownPool === shown) return;
    section.pinned = null;
    root.dataset.shownPool = shown;
    const built = controls.map((control) => build(section, control));
    tags.replaceChildren(...built.map(({ button }) => button));
    panels.replaceChildren(...built.map(({ panel }) => panel));
}

function onKeydown(section, event) {
    if (event.key !== 'Escape') return;
    const open = entries(section).find(({ panel }) => !panel.hidden);
    if (!open) return;
    const focusInPanel = open.panel.contains(document.activeElement);
    section.pinned = null;
    if (focusInPanel) open.button.focus();
    show(section, null);
}

export const PoolControls = {
    init() {
        const all = sections();
        for (const section of all) {
            section.root.addEventListener('keydown', (event) => onKeydown(section, event));
            // The section includes the gap and explanation, so moving from a
            // tag into its panel keeps the preview open for reading.
            section.root.addEventListener('pointerleave', (event) => {
                if (event.pointerType !== 'mouse' && event.pointerType !== 'pen') return;
                show(section, section.pinned);
            });
            section.root.addEventListener('focusout', (event) => {
                if (!section.root.contains(event.relatedTarget)) show(section, section.pinned);
            });
        }
        const renderAll = () => all.forEach(render);
        App.events.addEventListener('pool:config', renderAll);
        App.events.addEventListener('pool:selected', renderAll);
        renderAll();
    },
};
