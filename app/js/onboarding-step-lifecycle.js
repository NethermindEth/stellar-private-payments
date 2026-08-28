// Tracks which onboarding step currently owns the wizard's shared surface
// (error slot, action buttons, resolve/reject). Rejecting a step's promise
// does not stop its handler running; ownership is what a still-running
// handler must check before touching anything shared.
//
// No imports, so this loads under plain `node --test`; the wizard that uses
// it does not.

export function createStepLifecycle() {
    let issued = 0;
    let owner = null;
    let cancelled = false;

    return {
        begin() {
            issued += 1;
            owner = issued;
            return issued;
        },

        retire(token) {
            if (owner === token) owner = null;
        },

        isLive(token) {
            return !cancelled && owner !== null && owner === token;
        },

        cancel() {
            cancelled = true;
            owner = null;
        },

        isCancelled() {
            return cancelled;
        },
    };
}
