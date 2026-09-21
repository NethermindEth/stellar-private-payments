import { Templates } from './ui/templates.js';
import { Shell, Wallet } from './ui/navigation.js';
import { Transactions } from './ui/transactions.js';
import { SigningAccount } from './ui/signing-account.js';
import { RecipientAccount } from './ui/recipient-account.js';
import { NotesTable } from './ui/notes-table.js';
import { Dashboard } from './ui/dashboard.js';
import { updateLastVisit, registerServiceWorker } from './ui/push-notifications.js';
import { getConnectedAddress } from './wallet.js';
import { rememberedNoteOwner } from './account-session.js';

document.addEventListener('DOMContentLoaded', async () => {
    Templates.init();
    Shell.init();
    Wallet.init();
    Transactions.init();
    SigningAccount.init();
    RecipientAccount.init();
    NotesTable.init();
    Dashboard.init();

    updateLastVisit();
    registerServiceWorker();

    // Reconnect on load only to an owner the user connected before. Without
    // one, connecting would take Freighter's active account as the owner, and
    // that may be an account last used to sign; wait for the user to connect.
    if (rememberedNoteOwner() && await getConnectedAddress()) {
        Wallet.connect({ auto: true }).catch(() => {});
    }
});
