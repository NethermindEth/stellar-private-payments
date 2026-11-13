import { POOL_CONTROLS, poolControls } from '../pool-policy.js';
import { App } from './core.js';
import { el } from './dom.js';
import { TONES } from './pool-controls.js';
import { PoolDepositStatus } from './pool-deposit-status.js';

const entries = new WeakMap();
let open = null;
let closeTimer = null;

function close(restoreFocus = false) {
    clearTimeout(closeTimer);
    if (!open) return;
    const { trigger, panel } = open;
    const focusInside = panel.contains(document.activeElement);
    open = null;
    trigger.setAttribute('aria-expanded', 'false');
    panel.hidePopover();
    if (restoreFocus && focusInside && trigger.isConnected) trigger.focus({ preventScroll: true });
}

function position() {
    if (!open) return;
    const { trigger, panel } = open;
    // Opens the panel, or reopens it after moving its card removed it from the top layer.
    if (!panel.matches(':popover-open')) panel.showPopover();
    const viewport = window.visualViewport;
    const left = (viewport?.offsetLeft ?? 0) + 8;
    const top = (viewport?.offsetTop ?? 0) + 8;
    const right = left + (viewport?.width ?? window.innerWidth) - 16;
    const bottom = top + (viewport?.height ?? window.innerHeight) - 16;
    const rect = trigger.getBoundingClientRect();
    const width = Math.min(352, right - left);
    panel.style.width = `${width}px`;
    panel.style.maxHeight = `${bottom - top}px`;
    const height = panel.getBoundingClientRect().height;
    const below = Math.max(0, bottom - rect.bottom - 8);
    const above = Math.max(0, rect.top - top - 8);
    const flip = height > below && above > below;
    const available = Math.min(bottom - top, flip ? above : below);
    const panelHeight = Math.min(height, available);
    const y = flip ? rect.top - 8 - panelHeight : rect.bottom + 8;
    panel.style.maxHeight = `${available}px`;
    panel.style.left = `${Math.max(left, Math.min(rect.right - width, right - width))}px`;
    panel.style.top = `${Math.max(top, Math.min(y, bottom - panelHeight))}px`;
}

function show(entry) {
    clearTimeout(closeTimer);
    if (open === entry) return;
    close(true);
    open = entry;
    entry.trigger.setAttribute('aria-expanded', 'true');
    position();
}

function scheduleClose(entry) {
    clearTimeout(closeTimer);
    // Allow the pointer to cross the gap between the shield and its popup.
    closeTimer = setTimeout(() => {
        if (open === entry && !entry.hovered && !entry.panel.contains(document.activeElement)) close();
    }, 180);
}

function attach(card) {
    const trigger = card.querySelector('[data-overview-pool-controls]');
    // The top layer escapes the Overview container's backdrop filter, which
    // otherwise makes fixed positioning relative to that container.
    const panel = el('section', 'fixed inset-auto z-50 m-0 overflow-y-auto overscroll-contain rounded-2xl border border-white/10 bg-ink-850 p-4 text-sm text-slate-100 shadow-[0_16px_48px_rgba(0,0,0,0.5)]');
    panel.setAttribute('popover', 'manual');
    panel.id = `overview-pool-controls-${card.dataset.poolId}`;
    panel.setAttribute('aria-labelledby', `${panel.id}-heading`);
    trigger.setAttribute('aria-controls', panel.id);
    trigger.setAttribute('aria-expanded', 'false');
    trigger.after(panel);
    const entry = { trigger, panel, signature: null, poolId: card.dataset.poolId, hovered: false };
    entries.set(card, entry);
    for (const node of [trigger, panel]) {
        node.addEventListener('pointerenter', (event) => {
            if (event.pointerType !== 'mouse') return;
            entry.hovered = true;
            show(entry);
        });
        node.addEventListener('pointerleave', (event) => {
            if (event.pointerType !== 'mouse') return;
            entry.hovered = false;
            scheduleClose(entry);
        });
        node.addEventListener('focusout', () => {
            if (!entry.hovered) scheduleClose(entry);
        });
    }
    // Keep native activation for touch and keyboard. A mouse click on an
    // already hovered shield leaves its popup open.
    trigger.addEventListener('click', (event) => {
        if (entry.hovered && event.detail > 0) show(entry);
        else if (open === entry) close();
        else show(entry);
    });
    return entry;
}

function build({ trigger, panel, poolId }, controls) {
    trigger.setAttribute('aria-label', controls
        ? `Pool controls: ${controls.map((control) => POOL_CONTROLS[control].tag).join(', ')}`
        : 'Pool controls unavailable');
    const heading = el('h3', 'font-semibold text-white', 'Pool controls');
    heading.id = `${panel.id}-heading`;
    panel.replaceChildren(heading);
    if (!controls) {
        panel.append(el('p', 'mt-3 text-slate-300', 'Pool controls unavailable'));
        return;
    }
    for (const control of controls) {
        const { tag, impact } = POOL_CONTROLS[control];
        const row = el('div', 'mt-3');
        row.dataset.poolControlRow = '';
        const badge = el('span', 'chip px-2.5 py-1 text-xs font-semibold', tag);
        if (TONES[control]) badge.dataset.tone = TONES[control];
        row.append(
            badge,
            el('p', 'mt-2 text-sm leading-relaxed text-slate-300', impact),
        );
        panel.append(row);
    }
    // Text and tone are filled in by update(), which also refreshes them on status changes.
    const depositStatus = el('p', 'mt-3 border-t border-white/10 pt-3 text-sm leading-relaxed');
    depositStatus.dataset.overviewDepositStatus = '';
    depositStatus.setAttribute('role', 'status');
    const details = el('a', 'mt-4 inline-flex min-h-11 items-center text-sm font-semibold text-cyan-100 underline underline-offset-4 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-300/60', 'Details in Move funds');
    details.href = '#move-funds';
    details.addEventListener('click', (event) => {
        event.preventDefault();
        close();
        App.events.dispatchEvent(new CustomEvent('dashboard:view-pool-controls', { detail: { poolId } }));
    });
    panel.append(depositStatus, details);
}

export const OverviewPoolControls = {
    init() {
        document.addEventListener('click', (event) => {
            if (open && !open.trigger.contains(event.target) && !open.panel.contains(event.target)) close();
        });
        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape' && open) {
                event.preventDefault();
                close(true);
            }
        });
        window.addEventListener('scroll', position, true);
        window.addEventListener('resize', position);
        window.visualViewport?.addEventListener('scroll', position);
        window.visualViewport?.addEventListener('resize', position);
        App.events.addEventListener('view:changed', (event) => {
            if (event.detail.view !== 'dashboard') close();
        });
    },

    update(card) {
        const entry = entries.get(card) ?? attach(card);
        const pool = App.state.pools.find((pool) => pool.poolContractId === entry.poolId);
        const controls = pool ? poolControls(pool) : null;
        const signature = JSON.stringify(controls);
        if (signature !== entry.signature) {
            if (open === entry) close(true);
            entry.signature = signature;
            build(entry, controls);
        }
        const status = entry.panel.querySelector('[data-overview-deposit-status]');
        if (!status) return;
        PoolDepositStatus.renderDetail(status, entry.poolId, 'text-slate-300');
        if (open === entry) position();
    },

    remove(card) {
        if (open === entries.get(card)) close(true);
    },

    close,
    reposition: position,
};
