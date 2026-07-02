import { Templates } from './ui/templates.js';
import { Shell, Wallet } from './ui/navigation.js';
import { Transactions } from './ui/transactions.js';
import { NotesTable } from './ui/notes-table.js';
import { Dashboard } from './ui/dashboard.js';
import { updateLastVisit, registerServiceWorker } from './ui/push-notifications.js';

document.addEventListener('DOMContentLoaded', async () => {
    Templates.init();
    Shell.init();
    Wallet.init();
    Transactions.init();
    NotesTable.init();
    Dashboard.init();

    updateLastVisit();
    registerServiceWorker();

    Wallet.connect({ auto: true }).catch(() => {});
});
