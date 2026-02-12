/**
 * Freighter message protocol mock for Playwright addInitScript().
 *
 * The @stellar/freighter-api npm package communicates with the Freighter
 * browser extension via window.postMessage using:
 *   - Request: { source: "FREIGHTER_EXTERNAL_MSG_REQUEST", messageId, type, ... }
 *   - Response: { source: "FREIGHTER_EXTERNAL_MSG_RESPONSE", messagedId, ... }
 *
 * Note: "messagedId" (with typo) is the real protocol field name.
 *
 * Strategy:
 * Replace window.postMessage — intercept FREIGHTER_EXTERNAL_MSG_REQUEST
 * calls and dispatch a mock response via setTimeout(0). The original
 * postMessage is NOT called, so the content script (isolated world) never
 * sees the request and cannot send a competing response.
 *
 * Set window.freighter = true so isConnected() takes its fast synchronous
 * path without touching postMessage at all.
 */

/* eslint-disable no-undef */
function installFreighterMock(config) {
  const {
    publicKey = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    network = "TESTNET",
    networkUrl = "https://horizon-testnet.stellar.org",
    networkPassphrase = "Test SDF Network ; September 2015",
    sorobanRpcUrl = "https://soroban-testnet.stellar.org",
  } = config || {};

  // Fast path for isConnected(): returns synchronously without postMessage
  window.freighter = true;
  window.freighterApi = {};

  function buildResponse(messageId, type) {
    let payload = {};

    switch (type) {
      case "REQUEST_CONNECTION_STATUS":
        payload = { isConnected: true };
        break;
      case "REQUEST_ALLOWED_STATUS":
        payload = { isAllowed: true };
        break;
      case "SET_ALLOWED_STATUS":
        payload = { isAllowed: true };
        break;
      case "REQUEST_ACCESS":
      case "REQUEST_PUBLIC_KEY":
        payload = { publicKey };
        break;
      case "REQUEST_NETWORK_DETAILS":
        payload = {
          networkDetails: {
            network,
            networkUrl,
            networkPassphrase,
            sorobanRpcUrl,
          },
        };
        break;
      case "REQUEST_NETWORK":
        payload = { network };
        break;
      case "SUBMIT_TRANSACTION":
        payload = {
          signedTransaction: "AAAA_MOCK_SIGNED_TX_XDR",
          signerAddress: publicKey,
        };
        break;
      case "SUBMIT_AUTH_ENTRY":
        payload = {
          signedAuthEntry: "AAAA_MOCK_SIGNED_AUTH_ENTRY",
          signerAddress: publicKey,
        };
        break;
      case "SUBMIT_BLOB":
        // signMessage() uses SUBMIT_BLOB internally. The freighter-api maps
        // signedBlob → signedMessage, then the app does atob(signedMessage)
        // to derive keys. Must be valid base64, exactly 64 bytes (Ed25519).
        payload = {
          signedBlob:
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ==",
          signerAddress: publicKey,
        };
        break;
      case "REQUEST_USER_INFO":
        payload = { publicKey };
        break;
      default:
        console.warn("[FreighterMock] Unknown message type:", type);
    }

    return {
      source: "FREIGHTER_EXTERNAL_MSG_RESPONSE",
      messagedId: messageId,
      ...payload,
    };
  }

  // Replace postMessage to intercept Freighter API requests
  const originalPostMessage = window.postMessage.bind(window);

  window.postMessage = function (message, targetOrigin, transfer) {
    if (message && message.source === "FREIGHTER_EXTERNAL_MSG_REQUEST") {
      const { messageId, type } = message;
      // Do NOT call originalPostMessage — this prevents the content
      // script (isolated world) from ever seeing the request.
      // Dispatch mock response via setTimeout(0) so the freighter-api
      // has time to register its response listener first.
      const response = buildResponse(messageId, type);
      setTimeout(() => {
        originalPostMessage(response, window.location.origin);
      }, 0);
      return;
    }
    return originalPostMessage(message, targetOrigin, transfer);
  };
}

// Export for Node.js (used by fixtures.js to read the source)
if (typeof module !== "undefined" && module.exports) {
  module.exports = { installFreighterMock };
}
