import { startStorageAccess } from './storage-access-ui.js';

await startStorageAccess();
// Import only after unlocking: no wallet, sync, or application event handlers before this point.
if (document.body.dataset.application === 'admin') await import('./admin.js');
else await import('./ui.js');
