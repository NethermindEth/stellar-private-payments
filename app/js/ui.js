import { Templates } from './ui/templates.js';
import { Shell, Wallet } from './ui/navigation.js';
import { Transactions } from './ui/transactions.js';
import { NotesTable } from './ui/notes-table.js';
import { Dashboard } from './ui/dashboard.js';
import { updateLastVisit, registerServiceWorker } from './ui/push-notifications.js';
import { getConnectedAddress } from './wallet.js';

async function initializeApp() {
    Templates.init();
    Shell.init();
    Wallet.init();
    Transactions.init();
    NotesTable.init();
    Dashboard.init();

    updateLastVisit();
    registerServiceWorker();

    const existingAddress = await getConnectedAddress();
    if (existingAddress) {
        Wallet.connect({ auto: true }).catch(() => {});
    }
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initializeApp, { once: true });
else void initializeApp();
