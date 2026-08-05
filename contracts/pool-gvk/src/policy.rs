//! On-chain ASP policy flag bits stored as `u32`.

pub const ALLOWLIST_BIT: u32 = 1 << 0;
pub const BLOCKLIST_BIT: u32 = 1 << 1;
pub const MASK: u32 = ALLOWLIST_BIT | BLOCKLIST_BIT;

pub fn is_valid(flags: u32) -> bool {
    flags & !MASK == 0
}

pub fn requires_membership_proofs(flags: u32) -> bool {
    flags & ALLOWLIST_BIT != 0
}

pub fn requires_non_membership_proofs(flags: u32) -> bool {
    flags & BLOCKLIST_BIT != 0
}
