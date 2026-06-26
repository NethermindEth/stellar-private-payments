'use strict';

require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js');
require('buffer');
var curr_generated = require('../base/generated/curr_generated.js');
require('@noble/hashes/sha2.js');
require('../base/signing.js');
require('../base/keypair.js');
require('base32.js');
require('../base/util/continued_fraction.js');
require('../base/util/bignumber.js');
require('../base/transaction_builder.js');
require('../base/muxed_account.js');
var contract = require('../base/contract.js');
require('../base/scval.js');
var sorobandata_builder = require('../base/sorobandata_builder.js');
require('../base/numbers/uint128.js');
require('../base/numbers/uint256.js');
require('../base/numbers/int128.js');
require('../base/numbers/int256.js');
var api = require('./api.js');

function parseRawSendTransaction(raw) {
  const { errorResultXdr, diagnosticEventsXdr } = raw;
  delete raw.errorResultXdr;
  delete raw.diagnosticEventsXdr;
  if (errorResultXdr) {
    return {
      ...raw,
      ...diagnosticEventsXdr !== void 0 && diagnosticEventsXdr.length > 0 && {
        diagnosticEvents: diagnosticEventsXdr.map(
          (evt) => curr_generated.default.DiagnosticEvent.fromXDR(evt, "base64")
        )
      },
      errorResult: curr_generated.default.TransactionResult.fromXDR(errorResultXdr, "base64")
    };
  }
  return { ...raw };
}
function parseTransactionInfo(raw) {
  const meta = curr_generated.default.TransactionMeta.fromXDR(raw.resultMetaXdr, "base64");
  const info = {
    ledger: raw.ledger,
    createdAt: raw.createdAt,
    applicationOrder: raw.applicationOrder,
    feeBump: raw.feeBump,
    envelopeXdr: curr_generated.default.TransactionEnvelope.fromXDR(raw.envelopeXdr, "base64"),
    resultXdr: curr_generated.default.TransactionResult.fromXDR(raw.resultXdr, "base64"),
    resultMetaXdr: meta,
    events: {
      contractEventsXdr: (raw.events?.contractEventsXdr ?? []).map(
        (lst) => lst.map((e) => curr_generated.default.ContractEvent.fromXDR(e, "base64"))
      ),
      transactionEventsXdr: (raw.events?.transactionEventsXdr ?? []).map(
        (e) => curr_generated.default.TransactionEvent.fromXDR(e, "base64")
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
      (e) => curr_generated.default.DiagnosticEvent.fromXDR(e, "base64")
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
          contractId: new contract.Contract(evt.contractId)
        },
        topic: (evt.topic ?? []).map(
          (topic) => curr_generated.default.ScVal.fromXDR(topic, "base64")
        ),
        value: curr_generated.default.ScVal.fromXDR(evt.value, "base64")
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
        key: curr_generated.default.LedgerKey.fromXDR(rawEntry.key, "base64"),
        val: curr_generated.default.LedgerEntryData.fromXDR(rawEntry.xdr, "base64"),
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
    transactionData: new sorobandata_builder.SorobanDataBuilder(sim.transactionData),
    minResourceFee: sim.minResourceFee,
    // coalesce 0-or-1-element results[] list into a single result struct
    // with decoded fields if present
    ...(sim.results?.length ?? 0) > 0 && {
      result: sim.results.map((row) => ({
        auth: (row.auth ?? []).map(
          (entry) => curr_generated.default.SorobanAuthorizationEntry.fromXDR(entry, "base64")
        ),
        // if return value is missing ("falsy") we coalesce to void
        retval: row.xdr ? curr_generated.default.ScVal.fromXDR(row.xdr, "base64") : curr_generated.default.ScVal.scvVoid()
      }))[0]
    },
    ...(sim.stateChanges?.length ?? 0) > 0 && {
      stateChanges: sim.stateChanges?.map((entryChange) => ({
        type: entryChange.type,
        key: curr_generated.default.LedgerKey.fromXDR(entryChange.key, "base64"),
        before: entryChange.before ? curr_generated.default.LedgerEntry.fromXDR(entryChange.before, "base64") : null,
        after: entryChange.after ? curr_generated.default.LedgerEntry.fromXDR(entryChange.after, "base64") : null
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
      transactionData: new sorobandata_builder.SorobanDataBuilder(
        sim.restorePreamble.transactionData
      )
    }
  };
}
function parseRawSimulation(sim) {
  const looksRaw = api.Api.isSimulationRaw(sim);
  if (!looksRaw) {
    return sim;
  }
  const base = {
    _parsed: true,
    id: sim.id,
    latestLedger: sim.latestLedger,
    events: sim.events?.map((evt) => curr_generated.default.DiagnosticEvent.fromXDR(evt, "base64")) ?? []
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
  const metadataXdr = curr_generated.default.LedgerCloseMeta.fromXDR(raw.metadataXdr, "base64");
  const headerXdr = curr_generated.default.LedgerHeaderHistoryEntry.fromXDR(
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
  const headerXdr = curr_generated.default.LedgerHeader.fromXDR(raw.headerXdr, "base64");
  const metadataXdr = curr_generated.default.LedgerCloseMeta.fromXDR(raw.metadataXdr, "base64");
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

exports.parseRawEvents = parseRawEvents;
exports.parseRawLatestLedger = parseRawLatestLedger;
exports.parseRawLedger = parseRawLedger;
exports.parseRawLedgerEntries = parseRawLedgerEntries;
exports.parseRawSendTransaction = parseRawSendTransaction;
exports.parseRawSimulation = parseRawSimulation;
exports.parseRawTransactions = parseRawTransactions;
exports.parseTransactionInfo = parseTransactionInfo;
//# sourceMappingURL=parsers.js.map
