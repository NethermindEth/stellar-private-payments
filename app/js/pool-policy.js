import { Utils } from "./ui/core.js";

const CONTROL_LABELS = {
    open: "Open",
    allowlist: "Allowlist",
    blocklist: "Blocklist",
    viewOnly: "View-only",
    traceable: "Traceable",
};

/** Return all the flags of a pool. */
export function poolControls(pool) {
    const flags = pool.policyFlags ?? [];
    const controls =
        flags.length === 0
            ? ["open"]
            : ["allowlist", "blocklist"].filter((flag) => flags.includes(flag));
    if (pool.gvkMode === "viewOnly" || pool.gvkMode === "traceable")
        controls.push(pool.gvkMode);
    return controls;
}

function detailedLabel(
    pool,
    id = Utils.shortAddress(pool.poolContractId, 6, 4),
) {
    return [
        Utils.poolLabel(pool),
        id,
        ...poolControls(pool).map((control) => CONTROL_LABELS[control]),
    ].join(" · ");
}

/**
 * Construct the pool label. The label is composed of:
 * Token · address · [flags]
 * If two pools have the same short address, the full address is used instead
 */
export function poolSelectLabel(pool, pools) {
    const label = detailedLabel(pool);
    const collides = pools.some(
        (other) =>
            other.poolContractId !== pool.poolContractId &&
            detailedLabel(other) === label,
    );
    if (collides) {
        return detailedLabel(pool, pool.poolContractId);
    }
    return label;
}
