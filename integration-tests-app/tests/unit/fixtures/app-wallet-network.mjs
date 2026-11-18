let reply;
let config;

export function configure(networkReply, deploymentConfig) {
  reply = networkReply;
  config = deploymentConfig;
}

// Deliberately expose only SEP-0043 getNetwork for network queries. Importing
// the Varial-specific getNetworkDetails must fail the regression tests.
export async function getNetwork() { return reply; }
export async function loadDeploymentConfig() { return config; }
export class WatchWalletChanges {}
export const getAddress = () => {};
export const isAllowed = () => {};
export const isConnected = () => {};
export const requestAccess = () => {};
export const setAllowed = () => {};
export const signAuthEntry = () => {};
export const signTransaction = () => {};
export const signMessage = () => {};
