// Bookkeeping for mid-onboarding account switches: which account the wizard is
// working for, which switch is still pending, and whether the caller's debounce
// timer should be armed or cancelled.
//
// Timers are not owned here — the tracker returns 'arm' / 'cancel' / 'ignore'
// and the caller owns setTimeout, which keeps the decision synchronous and the
// tests free of fake timers.
//
// Kept in its own module because onboarding-wizard.js imports
// `stellar-private-payments/freighter` and cannot be loaded by plain
// `node --test`.

/**
 * @param {string} currentAddress the account onboarding is currently for
 */
export function createRebindTracker(currentAddress) {
    let current = currentAddress;
    let pending = null;

    return {
        /** The account onboarding is currently running for. */
        get current() {
            return current;
        },

        /** The switch waiting to be acted on, or null. */
        get pending() {
            return pending;
        },

        /**
         * Record an address the watcher just reported.
         *
         * Returns the action the caller must take on its debounce timer:
         * - 'arm'    a new switch is pending; (re)start the timer
         * - 'cancel' the pending switch is obsolete; stop the timer
         * - 'ignore' nothing changed
         *
         * An address equal to the current one is not "nothing to do": it means
         * a pending switch has been undone, so the timer must be cancelled.
         *
         * @param {string|null|undefined} next
         * @returns {'arm'|'cancel'|'ignore'}
         */
        observe(next) {
            if (!next) return 'ignore';
            if (next === current) {
                if (pending === null) return 'ignore';
                pending = null;
                return 'cancel';
            }
            pending = next;
            return 'arm';
        },

        /**
         * The address a firing debounce should signal, or null if the pending
         * switch stopped being a change while the timer ran.
         *
         * @returns {string|null}
         */
        dueAddress() {
            return pending !== null && pending !== current ? pending : null;
        },

        /**
         * Adopt the pending switch, making it current.
         *
         * @returns {string|null} the new address, or null if there was no
         * real switch to adopt.
         */
        adopt() {
            if (pending === null || pending === current) {
                pending = null;
                return null;
            }
            current = pending;
            pending = null;
            return current;
        },

        /**
         * Drop a pending value that is no longer a change, and ONLY that — a
         * switch that arrived during a replan must survive until it is adopted.
         */
        discardStale() {
            if (pending === current) pending = null;
        },
    };
}
