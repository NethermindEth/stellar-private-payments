import { DatabaseKeyVault, IndexedDbKeyStore } from 'stellar-private-payments/key-vault';
import { Storage } from 'stellar-private-payments';

async function openWithPassword(password: string) {
  const vault = new DatabaseKeyVault({ store: new IndexedDbKeyStore() });
  const unlocked = await vault.unlockPassword(password);
  const storage = await Storage.openEncrypted({ keyProvider: unlocked.keyProvider });
  await storage.close();
  unlocked.lock();
}
void openWithPassword;
