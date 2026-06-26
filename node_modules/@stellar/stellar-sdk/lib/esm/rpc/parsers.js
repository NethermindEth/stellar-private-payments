import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js';
import 'buffer';
import types from '../base/generated/curr_generated.js';
import '@noble/hashes/sha2.js';
import '../base/signing.js';
import '../base/keypair.js';
import 'base32.js';
import '../base/util/continued_fraction.js';
import '../base/util/bignumber.js';
import '../base/transaction_builder.js';
import '../base/muxed_account.js';
import { Contract } from '../base/contract.js';
import '../base/scval.js';
import { SorobanDataBuilder } from '../base/sorobandata_builder.js';
import '../base/numbers/uint128.js';
import '../base/numbers/uint256.js';
import '../base/numbers/int128.js';
import '../base/numbers/int256.js';
import { Api } from './api.js';

function parseRawSendTransaction(raw) {
  const { errorResultXdr, diagnosticEventsXdr } = raw;
  delete raw.errorResultXdr;
  delete raw.diagnosticEventsXdr;
  if (errorResultXdr) {
    return {
      ...raw,
      ...diagnosticEventsXdr !== void 0 && diagnosticEventsXdr.length > 0 && {
        diagnosticEvents: diagnosticEventsXdr.map(
          (evt) => types.DiagnosticEvent.fromXDR(evt, "base64")
        )
      },
      errorResult: types.TransactionResult.fromXDR(errorResultXdr, "base64")
    };
  }
  return { ...raw };
}
function parseTransactionInfo(raw) {
  const meta = types.TransactionMeta.fromXDR(raw.resultMetaXdr, "base64");
  const info = {
    ledger: raw.ledger,
    createdAt: raw.createdAt,
    applicationOrder: raw.applicationOrder,
    feeBump: raw.feeBump,
    envelopeXdr: types.TransactionEnvelope.fromXDR(raw.envelopeXdr, "base64"),
    resultXdr: types.TransactionResult.fromXDR(raw.resultXdr, "base64"),
    resultMetaXdr: meta,
    events: {
      contractEventsXdr: (raw.events?.contractEventsXdr ?? []).map(
        (lst) => lst.map((e) => types.ContractEvent.fromXDR(e, "base64"))
      ),
      transactionEventsXdr: (raw.events?.transactionEventsXdr ?? []).map(
        (e) => types.TransactionEvent.fromXDR(e, "base64")
      )
    }
  };
  switch (meta.switch()) {
    case 3:
    case 4: {
      const metaV = meta.value();
      if (metaV.sorobanMeta() !== null) {
        info.returnValue = metaV.sorobanMeta()?.returnValue() ?? void 0;
      }
    }
  }
  if (raw.diagnosticEventsXdr) {
    info.diagnosticEventsXdr = raw.diagnosticEventsXdr.map(
      (e) => types.DiagnosticEvent.fromXDR(e, "base64")
    );
  }
  return info;
}
function parseRawTransactions(r) {
  return {
    status: r.status,
    txHash: r.txHash,
    ...parseTransactionInfo(r)
  };
}
function parseRawEvents(raw) {
  return {
    latestLedger: raw.latestLedger,
    oldestLedger: raw.oldestLedger,
    latestLedgerCloseTime: raw.latestLedgerCloseTime,
    oldestLedgerCloseTime: raw.oldestLedgerCloseTime,
    cursor: raw.cursor,
    events: (raw.events ?? []).map((evt) => {
      const clone = { ...evt };
      delete clone.contractId;
      return {
        ...clone,
        ...evt.contractId !== "" && {
          contractId: new Contract(evt.contractId)
        },
        topic: (evt.topic ?? []).map(
          (topic) => types.ScVal.fromXDR(topic, "base64")
        ),
        value: types.ScVal.fromXDR(evt.value, "base64")
      };
    })
  };
}
function parseRawLedgerEntries(raw) {
  return {
    latestLedger: raw.latestLedger,
    entries: (raw.entries ?? []).map((rawEntry) => {
      if (!rawEntry.key || !rawEntry.xdr) {
        throw new TypeError(
          `invalid ledger entry: ${JSON.stringify(rawEntry)}`
        );
      }
      return {
        lastModifiedLedgerSeq: rawEntry.lastModifiedLedgerSeq,
        key: types.LedgerKey.fromXDR(rawEntry.key, "base64"),
        val: types.LedgerEntryData.fromXDR(rawEntry.xdr, "base64"),
        ...rawEntry.liveUntilLedgerSeq !== void 0 && {
          liveUntilLedgerSeq: rawEntry.liveUntilLedgerSeq
        }
      };
    })
  };
}
function parseSuccessful(sim, partial) {
  const success = {
    ...partial,
    transactionData: new SorobanDataBuilder(sim.transactionData),
    minResourceFee: sim.minResourceFee,
    // coalesce 0-or-1-element results[] list into a single result struct
    // with decoded fields if present
    ...(sim.results?.length ?? 0) > 0 && {
      result: sim.results.map((row) => ({
        auth: (row.auth ?? []).map(
          (entry) => types.SorobanAuthorizationEntry.fromXDR(entry, "base64")
        ),
        // if return value is missing ("falsy") we coalesce to void
        retval: row.xdr ? types.ScVal.fromXDR(row.xdr, "base64") : types.ScVal.scvVoid()
      }))[0]
    },
    ...(sim.stateChanges?.length ?? 0) > 0 && {
      stateChanges: sim.stateChanges?.map((entryChange) => ({
        type: entryChange.type,
        key: types.LedgerKey.fromXDR(entryChange.key, "base64"),
        before: entryChange.before ? types.LedgerEntry.fromXDR(entryChange.before, "base64") : null,
        after: entryChange.after ? types.LedgerEntry.fromXDR(entryChange.after, "base64") : null
      }))
    }
  };
  if (!sim.restorePreamble || sim.restorePreamble.transactionData === "") {
    return success;
  }
  return {
    ...success,
    restorePreamble: {
      minResourceFee: sim.restorePreamble.minResourceFee,
      transactionData: new SorobanDataBuilder(
        sim.restorePreamble.transactionData
      )
    }
  };
}
function parseRawSimulation(sim) {
  const looksRaw = Api.isSimulationRaw(sim);
  if (!looksRaw) {
    return sim;
  }
  const base = {
    _parsed: true,
    id: sim.id,
    latestLedger: sim.latestLedger,
    events: sim.events?.map((evt) => types.DiagnosticEvent.fromXDR(evt, "base64")) ?? []
  };
  if (typeof sim.error === "string") {
    return {
      ...base,
      error: sim.error
    };
  }
  return parseSuccessful(sim, base);
}
function parseRawLedger(raw) {
  if (!raw.metadataXdr || !raw.headerXdr) {
    let missingFields;
    if (!raw.metadataXdr && !raw.headerXdr) {
      missingFields = "metadataXdr and headerXdr";
    } else if (!raw.metadataXdr) {
      missingFields = "metadataXdr";
    } else {
      missingFields = "headerXdr";
    }
    throw new TypeError(`invalid ledger missing fields: ${missingFields}`);
  }
  const metadataXdr = types.LedgerCloseMeta.fromXDR(raw.metadataXdr, "base64");
  const headerXdr = types.LedgerHeaderHistoryEntry.fromXDR(
    raw.headerXdr,
    "base64"
  );
  return {
    hash: raw.hash,
    sequence: raw.sequence,
    ledgerCloseTime: raw.ledgerCloseTime,
    metadataXdr,
    headerXdr
  };
}
function parseRawLatestLedger(raw) {
  const headerXdr = types.LedgerHeader.fromXDR(raw.headerXdr, "base64");
  const metadataXdr = types.LedgerCloseMeta.fromXDR(raw.metadataXdr, "base64");
  let missingFields;
  if (!raw.metadataXdr && !raw.headerXdr) {
    missingFields = "metadataXdr and headerXdr";
  } else if (!raw.metadataXdr) {
    missingFields = "metadataXdr";
  } else if (!raw.headerXdr) {
    missingFields = "headerXdr";
  }
  if (missingFields) {
    throw new TypeError(
      `invalid getLatestLedger response missing fields: ${missingFields}`
    );
  }
  return {
    id: raw.id,
    sequence: raw.sequence,
    protocolVersion: raw.protocolVersion,
    closeTime: raw.closeTime,
    headerXdr,
    metadataXdr
  };
}

export { parseRawEvents, parseRawLatestLedger, parseRawLedger, parseRawLedgerEntries, parseRawSendTransaction, parseRawSimulation, parseRawTransactions, parseTransactionInfo };
//# sourceMappingURL=parsers.js.map
