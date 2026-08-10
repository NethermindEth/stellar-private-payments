/**
 * Shared keyboard helpers.
 *
 * Kept dependency-free so it can be imported from every esbuild entry point
 * (ui.js and disclosure.js have separate module graphs).
 *
 * @module ui/keys
 */

/**
 * Run `handler` when Enter is pressed in `input`.
 *
 * The default action is suppressed so Enter never submits an enclosing form.
 *
 * @param {HTMLElement | null | undefined} input
 * @param {() => void} handler
 */
export function onEnter(input, handler) {
    input?.addEventListener('keydown', (event) => {
        if (event.key !== 'Enter') return;
        event.preventDefault();
        handler();
    });
}
