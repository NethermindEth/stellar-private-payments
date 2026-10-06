const EXPLORER_KEY = 'spp.explorerBaseUrl';
export function explorerPreference(records = localStorage) {
    try { return records.getItem(EXPLORER_KEY); } catch { return null; }
}
export function saveExplorerPreference(value, records = localStorage) {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) {
        throw new Error('Explorer URL must use HTTPS without credentials, query parameters or a fragment.');
    }
    records.setItem(EXPLORER_KEY, value);
}
