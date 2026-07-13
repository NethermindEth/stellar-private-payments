/// How the pool keeps local storage in sync with on-chain contract events
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    /// The pool runs [`PrivatePool::sync`] inline when needed.
    /// No separate background sync task is required.
    Inline,
    /// Storage is kept in sync by a background task you start separately.
    Background,
}
