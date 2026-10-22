import { Utils } from "./ui/core.js";

/**
 * Mapping containing the label and a long and short description of each tag
 */
export const POOL_CONTROLS = {
    open: {
        label: "Open",
        tag: "Open",
        explanation: "This pool has no allowlist or blocklist requirements.",
        impact: "Pool access: no allowlist or blocklist.",
    },
    allowlist: {
        label: "Allowlist",
        tag: "Allowlist",
        explanation:
            "This pool requires public keys to be on the ASP allowlist.",
        impact: "Pool access: required to be on the ASP allowlist.",
    },
    blocklist: {
        label: "Blocklist",
        tag: "Blocklist",
        explanation:
            "This pool requires public keys to NOT be on the ASP blocklist.",
        impact: "Pool access: required to NOT be on the ASP blocklist.",
    },
    viewOnly: {
        label: "View-only",
        tag: "Admin view key · view-only",
        explanation:
            "Notes are encrypted with the pool's admin view key, revealing only the owner public key and the amount.",
        impact: "Privacy: the admin view key holder can read every new note.",
    },
    traceable: {
        label: "Traceable",
        tag: "Admin view key · traceable",
        explanation:
            "Notes are encrypted with the pool’s admin view key. Key holders can view owner public keys and amounts, link spent notes, and trace funds across transactions.",
        impact: "Privacy: the admin view key holder can trace funds through the pool.",
    },
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
        ...poolControls(pool).map((control) => POOL_CONTROLS[control].label),
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
