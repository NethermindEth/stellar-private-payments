import { DatabaseKeyVault, IndexedDbKeyStore } from 'stellar-private-payments/key-vault';
import { Storage } from 'stellar-private-payments';
import { FreighterSigner } from 'stellar-private-payments/freighter';

async function openWithPassword(password: string) {
  const vault = new DatabaseKeyVault({ store: new IndexedDbKeyStore() });
  const unlocked = await vault.unlockPassword(password);
  const storage = await Storage.openEncrypted({ keyProvider: unlocked.keyProvider });
  await storage.close();
  unlocked.lock();
}
void openWithPassword;

async function enrollAndOpenWithWallet(password: string) {
  const vault = new DatabaseKeyVault();
  const signer = new FreighterSigner();
  await vault.addWallet(password, signer);
  const session = await vault.unlockWallet(signer);
  const storage = await Storage.openEncrypted({ keyProvider: session.keyProvider });
  await storage.close();
  session.lock();
  await vault.removeWallet(password);
}
void enrollAndOpenWithWallet;
