'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

require('../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js');
require('../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js');
require('../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js');
require('../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js');
require('../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js');
require('buffer');
var config = require('../../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/config.js');

var types = config.config((xdr) => {
  const SCSYMBOL_LIMIT = 32;
  const SC_SPEC_DOC_LIMIT = 1024;
  xdr.typedef("Value", xdr.varOpaque());
  xdr.struct("ScpBallot", [
    ["counter", xdr.lookup("Uint32")],
    ["value", xdr.lookup("Value")]
  ]);
  xdr.enum("ScpStatementType", {
    scpStPrepare: 0,
    scpStConfirm: 1,
    scpStExternalize: 2,
    scpStNominate: 3
  });
  xdr.struct("ScpNomination", [
    ["quorumSetHash", xdr.lookup("Hash")],
    ["votes", xdr.varArray(xdr.lookup("Value"), 2147483647)],
    ["accepted", xdr.varArray(xdr.lookup("Value"), 2147483647)]
  ]);
  xdr.struct("ScpStatementPrepare", [
    ["quorumSetHash", xdr.lookup("Hash")],
    ["ballot", xdr.lookup("ScpBallot")],
    ["prepared", xdr.option(xdr.lookup("ScpBallot"))],
    ["preparedPrime", xdr.option(xdr.lookup("ScpBallot"))],
    ["nC", xdr.lookup("Uint32")],
    ["nH", xdr.lookup("Uint32")]
  ]);
  xdr.struct("ScpStatementConfirm", [
    ["ballot", xdr.lookup("ScpBallot")],
    ["nPrepared", xdr.lookup("Uint32")],
    ["nCommit", xdr.lookup("Uint32")],
    ["nH", xdr.lookup("Uint32")],
    ["quorumSetHash", xdr.lookup("Hash")]
  ]);
  xdr.struct("ScpStatementExternalize", [
    ["commit", xdr.lookup("ScpBallot")],
    ["nH", xdr.lookup("Uint32")],
    ["commitQuorumSetHash", xdr.lookup("Hash")]
  ]);
  xdr.union("ScpStatementPledges", {
    switchOn: xdr.lookup("ScpStatementType"),
    switchName: "type",
    switches: [
      ["scpStPrepare", "prepare"],
      ["scpStConfirm", "confirm"],
      ["scpStExternalize", "externalize"],
      ["scpStNominate", "nominate"]
    ],
    arms: {
      prepare: xdr.lookup("ScpStatementPrepare"),
      confirm: xdr.lookup("ScpStatementConfirm"),
      externalize: xdr.lookup("ScpStatementExternalize"),
      nominate: xdr.lookup("ScpNomination")
    }
  });
  xdr.struct("ScpStatement", [
    ["nodeId", xdr.lookup("NodeId")],
    ["slotIndex", xdr.lookup("Uint64")],
    ["pledges", xdr.lookup("ScpStatementPledges")]
  ]);
  xdr.struct("ScpEnvelope", [
    ["statement", xdr.lookup("ScpStatement")],
    ["signature", xdr.lookup("Signature")]
  ]);
  xdr.struct("ScpQuorumSet", [
    ["threshold", xdr.lookup("Uint32")],
    ["validators", xdr.varArray(xdr.lookup("NodeId"), 2147483647)],
    ["innerSets", xdr.varArray(xdr.lookup("ScpQuorumSet"), 2147483647)]
  ]);
  xdr.typedef("Thresholds", xdr.opaque(4));
  xdr.typedef("String32", xdr.string(32));
  xdr.typedef("String64", xdr.string(64));
  xdr.typedef("SequenceNumber", xdr.lookup("Int64"));
  xdr.typedef("DataValue", xdr.varOpaque(64));
  xdr.typedef("AssetCode4", xdr.opaque(4));
  xdr.typedef("AssetCode12", xdr.opaque(12));
  xdr.enum("AssetType", {
    assetTypeNative: 0,
    assetTypeCreditAlphanum4: 1,
    assetTypeCreditAlphanum12: 2,
    assetTypePoolShare: 3
  });
  xdr.union("AssetCode", {
    switchOn: xdr.lookup("AssetType"),
    switchName: "type",
    switches: [
      ["assetTypeCreditAlphanum4", "assetCode4"],
      ["assetTypeCreditAlphanum12", "assetCode12"]
    ],
    arms: {
      assetCode4: xdr.lookup("AssetCode4"),
      assetCode12: xdr.lookup("AssetCode12")
    }
  });
  xdr.struct("AlphaNum4", [
    ["assetCode", xdr.lookup("AssetCode4")],
    ["issuer", xdr.lookup("AccountId")]
  ]);
  xdr.struct("AlphaNum12", [
    ["assetCode", xdr.lookup("AssetCode12")],
    ["issuer", xdr.lookup("AccountId")]
  ]);
  xdr.union("Asset", {
    switchOn: xdr.lookup("AssetType"),
    switchName: "type",
    switches: [
      ["assetTypeNative", xdr.void()],
      ["assetTypeCreditAlphanum4", "alphaNum4"],
      ["assetTypeCreditAlphanum12", "alphaNum12"]
    ],
    arms: {
      alphaNum4: xdr.lookup("AlphaNum4"),
      alphaNum12: xdr.lookup("AlphaNum12")
    }
  });
  xdr.struct("Price", [
    ["n", xdr.lookup("Int32")],
    ["d", xdr.lookup("Int32")]
  ]);
  xdr.struct("Liabilities", [
    ["buying", xdr.lookup("Int64")],
    ["selling", xdr.lookup("Int64")]
  ]);
  xdr.enum("ThresholdIndices", {
    thresholdMasterWeight: 0,
    thresholdLow: 1,
    thresholdMed: 2,
    thresholdHigh: 3
  });
  xdr.enum("LedgerEntryType", {
    account: 0,
    trustline: 1,
    offer: 2,
    data: 3,
    claimableBalance: 4,
    liquidityPool: 5,
    contractData: 6,
    contractCode: 7,
    configSetting: 8,
    ttl: 9
  });
  xdr.struct("Signer", [
    ["key", xdr.lookup("SignerKey")],
    ["weight", xdr.lookup("Uint32")]
  ]);
  xdr.enum("AccountFlags", {
    authRequiredFlag: 1,
    authRevocableFlag: 2,
    authImmutableFlag: 4,
    authClawbackEnabledFlag: 8
  });
  xdr.const("MASK_ACCOUNT_FLAGS", 7);
  xdr.const("MASK_ACCOUNT_FLAGS_V17", 15);
  xdr.const("MAX_SIGNERS", 20);
  xdr.typedef("SponsorshipDescriptor", xdr.option(xdr.lookup("AccountId")));
  xdr.struct("AccountEntryExtensionV3", [
    ["ext", xdr.lookup("ExtensionPoint")],
    ["seqLedger", xdr.lookup("Uint32")],
    ["seqTime", xdr.lookup("TimePoint")]
  ]);
  xdr.union("AccountEntryExtensionV2Ext", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [
      [0, xdr.void()],
      [3, "v3"]
    ],
    arms: {
      v3: xdr.lookup("AccountEntryExtensionV3")
    }
  });
  xdr.struct("AccountEntryExtensionV2", [
    ["numSponsored", xdr.lookup("Uint32")],
    ["numSponsoring", xdr.lookup("Uint32")],
    [
      "signerSponsoringIDs",
      xdr.varArray(
        xdr.lookup("SponsorshipDescriptor"),
        xdr.lookup("MAX_SIGNERS")
      )
    ],
    ["ext", xdr.lookup("AccountEntryExtensionV2Ext")]
  ]);
  xdr.union("AccountEntryExtensionV1Ext", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [
      [0, xdr.void()],
      [2, "v2"]
    ],
    arms: {
      v2: xdr.lookup("AccountEntryExtensionV2")
    }
  });
  xdr.struct("AccountEntryExtensionV1", [
    ["liabilities", xdr.lookup("Liabilities")],
    ["ext", xdr.lookup("AccountEntryExtensionV1Ext")]
  ]);
  xdr.union("AccountEntryExt", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [
      [0, xdr.void()],
      [1, "v1"]
    ],
    arms: {
      v1: xdr.lookup("AccountEntryExtensionV1")
    }
  });
  xdr.struct("AccountEntry", [
    ["accountId", xdr.lookup("AccountId")],
    ["balance", xdr.lookup("Int64")],
    ["seqNum", xdr.lookup("SequenceNumber")],
    ["numSubEntries", xdr.lookup("Uint32")],
    ["inflationDest", xdr.option(xdr.lookup("AccountId"))],
    ["flags", xdr.lookup("Uint32")],
    ["homeDomain", xdr.lookup("String32")],
    ["thresholds", xdr.lookup("Thresholds")],
    ["signers", xdr.varArray(xdr.lookup("Signer"), xdr.lookup("MAX_SIGNERS"))],
    ["ext", xdr.lookup("AccountEntryExt")]
  ]);
  xdr.enum("TrustLineFlags", {
    authorizedFlag: 1,
    authorizedToMaintainLiabilitiesFlag: 2,
    trustlineClawbackEnabledFlag: 4
  });
  xdr.const("MASK_TRUSTLINE_FLAGS", 1);
  xdr.const("MASK_TRUSTLINE_FLAGS_V13", 3);
  xdr.const("MASK_TRUSTLINE_FLAGS_V17", 7);
  xdr.enum("LiquidityPoolType", {
    liquidityPoolConstantProduct: 0
  });
  xdr.union("TrustLineAsset", {
    switchOn: xdr.lookup("AssetType"),
    switchName: "type",
    switches: [
      ["assetTypeNative", xdr.void()],
      ["assetTypeCreditAlphanum4", "alphaNum4"],
      ["assetTypeCreditAlphanum12", "alphaNum12"],
      ["assetTypePoolShare", "liquidityPoolId"]
    ],
    arms: {
      alphaNum4: xdr.lookup("AlphaNum4"),
      alphaNum12: xdr.lookup("AlphaNum12"),
      liquidityPoolId: xdr.lookup("PoolId")
    }
  });
  xdr.union("TrustLineEntryExtensionV2Ext", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [[0, xdr.void()]],
    arms: {}
  });
  xdr.struct("TrustLineEntryExtensionV2", [
    ["liquidityPoolUseCount", xdr.lookup("Int32")],
    ["ext", xdr.lookup("TrustLineEntryExtensionV2Ext")]
  ]);
  xdr.union("TrustLineEntryV1Ext", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [
      [0, xdr.void()],
      [2, "v2"]
    ],
    arms: {
      v2: xdr.lookup("TrustLineEntryExtensionV2")
    }
  });
  xdr.struct("TrustLineEntryV1", [
    ["liabilities", xdr.lookup("Liabilities")],
    ["ext", xdr.lookup("TrustLineEntryV1Ext")]
  ]);
  xdr.union("TrustLineEntryExt", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [
      [0, xdr.void()],
      [1, "v1"]
    ],
    arms: {
      v1: xdr.lookup("TrustLineEntryV1")
    }
  });
  xdr.struct("TrustLineEntry", [
    ["accountId", xdr.lookup("AccountId")],
    ["asset", xdr.lookup("TrustLineAsset")],
    ["balance", xdr.lookup("Int64")],
    ["limit", xdr.lookup("Int64")],
    ["flags", xdr.lookup("Uint32")],
    ["ext", xdr.lookup("TrustLineEntryExt")]
  ]);
  xdr.enum("OfferEntryFlags", {
    passiveFlag: 1
  });
  xdr.const("MASK_OFFERENTRY_FLAGS", 1);
  xdr.union("OfferEntryExt", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [[0, xdr.void()]],
    arms: {}
  });
  xdr.struct("OfferEntry", [
    ["sellerId", xdr.lookup("AccountId")],
    ["offerId", xdr.lookup("Int64")],
    ["selling", xdr.lookup("Asset")],
    ["buying", xdr.lookup("Asset")],
    ["amount", xdr.lookup("Int64")],
    ["price", xdr.lookup("Price")],
    ["flags", xdr.lookup("Uint32")],
    ["ext", xdr.lookup("OfferEntryExt")]
  ]);
  xdr.union("DataEntryExt", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [[0, xdr.void()]],
    arms: {}
  });
  xdr.struct("DataEntry", [
    ["accountId", xdr.lookup("AccountId")],
    ["dataName", xdr.lookup("String64")],
    ["dataValue", xdr.lookup("DataValue")],
    ["ext", xdr.lookup("DataEntryExt")]
  ]);
  xdr.enum("ClaimPredicateType", {
    claimPredicateUnconditional: 0,
    claimPredicateAnd: 1,
    claimPredicateOr: 2,
    claimPredicateNot: 3,
    claimPredicateBeforeAbsoluteTime: 4,
    claimPredicateBeforeRelativeTime: 5
  });
  xdr.union("ClaimPredicate", {
    switchOn: xdr.lookup("ClaimPredicateType"),
    switchName: "type",
    switches: [
      ["claimPredicateUnconditional", xdr.void()],
      ["claimPredicateAnd", "andPredicates"],
      ["claimPredicateOr", "orPredicates"],
      ["claimPredicateNot", "notPredicate"],
      ["claimPredicateBeforeAbsoluteTime", "absBefore"],
      ["claimPredicateBeforeRelativeTime", "relBefore"]
    ],
    arms: {
      andPredicates: xdr.varArray(xdr.lookup("ClaimPredicate"), 2),
      orPredicates: xdr.varArray(xdr.lookup("ClaimPredicate"), 2),
      notPredicate: xdr.option(xdr.lookup("ClaimPredicate")),
      absBefore: xdr.lookup("Int64"),
      relBefore: xdr.lookup("Int64")
    }
  });
  xdr.enum("ClaimantType", {
    claimantTypeV0: 0
  });
  xdr.struct("ClaimantV0", [
    ["destination", xdr.lookup("AccountId")],
    ["predicate", xdr.lookup("ClaimPredicate")]
  ]);
  xdr.union("Claimant", {
    switchOn: xdr.lookup("ClaimantType"),
    switchName: "type",
    switches: [["claimantTypeV0", "v0"]],
    arms: {
      v0: xdr.lookup("ClaimantV0")
    }
  });
  xdr.enum("ClaimableBalanceFlags", {
    claimableBalanceClawbackEnabledFlag: 1
  });
  xdr.const("MASK_CLAIMABLE_BALANCE_FLAGS", 1);
  xdr.union("ClaimableBalanceEntryExtensionV1Ext", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [[0, xdr.void()]],
    arms: {}
  });
  xdr.struct("ClaimableBalanceEntryExtensionV1", [
    ["ext", xdr.lookup("ClaimableBalanceEntryExtensionV1Ext")],
    ["flags", xdr.lookup("Uint32")]
  ]);
  xdr.union("ClaimableBalanceEntryExt", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [
      [0, xdr.void()],
      [1, "v1"]
    ],
    arms: {
      v1: xdr.lookup("ClaimableBalanceEntryExtensionV1")
    }
  });
  xdr.struct("ClaimableBalanceEntry", [
    ["balanceId", xdr.lookup("ClaimableBalanceId")],
    ["claimants", xdr.varArray(xdr.lookup("Claimant"), 10)],
    ["asset", xdr.lookup("Asset")],
    ["amount", xdr.lookup("Int64")],
    ["ext", xdr.lookup("ClaimableBalanceEntryExt")]
  ]);
  xdr.struct("LiquidityPoolConstantProductParameters", [
    ["assetA", xdr.lookup("Asset")],
    ["assetB", xdr.lookup("Asset")],
    ["fee", xdr.lookup("Int32")]
  ]);
  xdr.struct("LiquidityPoolEntryConstantProduct", [
    ["params", xdr.lookup("LiquidityPoolConstantProductParameters")],
    ["reserveA", xdr.lookup("Int64")],
    ["reserveB", xdr.lookup("Int64")],
    ["totalPoolShares", xdr.lookup("Int64")],
    ["poolSharesTrustLineCount", xdr.lookup("Int64")]
  ]);
  xdr.union("LiquidityPoolEntryBody", {
    switchOn: xdr.lookup("LiquidityPoolType"),
    switchName: "type",
    switches: [["liquidityPoolConstantProduct", "constantProduct"]],
    arms: {
      constantProduct: xdr.lookup("LiquidityPoolEntryConstantProduct")
    }
  });
  xdr.struct("LiquidityPoolEntry", [
    ["liquidityPoolId", xdr.lookup("PoolId")],
    ["body", xdr.lookup("LiquidityPoolEntryBody")]
  ]);
  xdr.enum("ContractDataDurability", {
    temporary: 0,
    persistent: 1
  });
  xdr.struct("ContractDataEntry", [
    ["ext", xdr.lookup("ExtensionPoint")],
    ["contract", xdr.lookup("ScAddress")],
    ["key", xdr.lookup("ScVal")],
    ["durability", xdr.lookup("ContractDataDurability")],
    ["val", xdr.lookup("ScVal")]
  ]);
  xdr.struct("ContractCodeCostInputs", [
    ["ext", xdr.lookup("ExtensionPoint")],
    ["nInstructions", xdr.lookup("Uint32")],
    ["nFunctions", xdr.lookup("Uint32")],
    ["nGlobals", xdr.lookup("Uint32")],
    ["nTableEntries", xdr.lookup("Uint32")],
    ["nTypes", xdr.lookup("Uint32")],
    ["nDataSegments", xdr.lookup("Uint32")],
    ["nElemSegments", xdr.lookup("Uint32")],
    ["nImports", xdr.lookup("Uint32")],
    ["nExports", xdr.lookup("Uint32")],
    ["nDataSegmentBytes", xdr.lookup("Uint32")]
  ]);
  xdr.struct("ContractCodeEntryV1", [
    ["ext", xdr.lookup("ExtensionPoint")],
    ["costInputs", xdr.lookup("ContractCodeCostInputs")]
  ]);
  xdr.union("ContractCodeEntryExt", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [
      [0, xdr.void()],
      [1, "v1"]
    ],
    arms: {
      v1: xdr.lookup("ContractCodeEntryV1")
    }
  });
  xdr.struct("ContractCodeEntry", [
    ["ext", xdr.lookup("ContractCodeEntryExt")],
    ["hash", xdr.lookup("Hash")],
    ["code", xdr.varOpaque()]
  ]);
  xdr.struct("TtlEntry", [
    ["keyHash", xdr.lookup("Hash")],
    ["liveUntilLedgerSeq", xdr.lookup("Uint32")]
  ]);
  xdr.union("LedgerEntryExtensionV1Ext", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [[0, xdr.void()]],
    arms: {}
  });
  xdr.struct("LedgerEntryExtensionV1", [
    ["sponsoringId", xdr.lookup("SponsorshipDescriptor")],
    ["ext", xdr.lookup("LedgerEntryExtensionV1Ext")]
  ]);
  xdr.union("LedgerEntryData", {
    switchOn: xdr.lookup("LedgerEntryType"),
    switchName: "type",
    switches: [
      ["account", "account"],
      ["trustline", "trustLine"],
      ["offer", "offer"],
      ["data", "data"],
      ["claimableBalance", "claimableBalance"],
      ["liquidityPool", "liquidityPool"],
      ["contractData", "contractData"],
      ["contractCode", "contractCode"],
      ["configSetting", "configSetting"],
      ["ttl", "ttl"]
    ],
    arms: {
      account: xdr.lookup("AccountEntry"),
      trustLine: xdr.lookup("TrustLineEntry"),
      offer: xdr.lookup("OfferEntry"),
      data: xdr.lookup("DataEntry"),
      claimableBalance: xdr.lookup("ClaimableBalanceEntry"),
      liquidityPool: xdr.lookup("LiquidityPoolEntry"),
      contractData: xdr.lookup("ContractDataEntry"),
      contractCode: xdr.lookup("ContractCodeEntry"),
      configSetting: xdr.lookup("ConfigSettingEntry"),
      ttl: xdr.lookup("TtlEntry")
    }
  });
  xdr.union("LedgerEntryExt", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [
      [0, xdr.void()],
      [1, "v1"]
    ],
    arms: {
      v1: xdr.lookup("LedgerEntryExtensionV1")
    }
  });
  xdr.struct("LedgerEntry", [
    ["lastModifiedLedgerSeq", xdr.lookup("Uint32")],
    ["data", xdr.lookup("LedgerEntryData")],
    ["ext", xdr.lookup("LedgerEntryExt")]
  ]);
  xdr.struct("LedgerKeyAccount", [["accountId", xdr.lookup("AccountId")]]);
  xdr.struct("LedgerKeyTrustLine", [
    ["accountId", xdr.lookup("AccountId")],
    ["asset", xdr.lookup("TrustLineAsset")]
  ]);
  xdr.struct("LedgerKeyOffer", [
    ["sellerId", xdr.lookup("AccountId")],
    ["offerId", xdr.lookup("Int64")]
  ]);
  xdr.struct("LedgerKeyData", [
    ["accountId", xdr.lookup("AccountId")],
    ["dataName", xdr.lookup("String64")]
  ]);
  xdr.struct("LedgerKeyClaimableBalance", [
    ["balanceId", xdr.lookup("ClaimableBalanceId")]
  ]);
  xdr.struct("LedgerKeyLiquidityPool", [
    ["liquidityPoolId", xdr.lookup("PoolId")]
  ]);
  xdr.struct("LedgerKeyContractData", [
    ["contract", xdr.lookup("ScAddress")],
    ["key", xdr.lookup("ScVal")],
    ["durability", xdr.lookup("ContractDataDurability")]
  ]);
  xdr.struct("LedgerKeyContractCode", [["hash", xdr.lookup("Hash")]]);
  xdr.struct("LedgerKeyConfigSetting", [
    ["configSettingId", xdr.lookup("ConfigSettingId")]
  ]);
  xdr.struct("LedgerKeyTtl", [["keyHash", xdr.lookup("Hash")]]);
  xdr.union("LedgerKey", {
    switchOn: xdr.lookup("LedgerEntryType"),
    switchName: "type",
    switches: [
      ["account", "account"],
      ["trustline", "trustLine"],
      ["offer", "offer"],
      ["data", "data"],
      ["claimableBalance", "claimableBalance"],
      ["liquidityPool", "liquidityPool"],
      ["contractData", "contractData"],
      ["contractCode", "contractCode"],
      ["configSetting", "configSetting"],
      ["ttl", "ttl"]
    ],
    arms: {
      account: xdr.lookup("LedgerKeyAccount"),
      trustLine: xdr.lookup("LedgerKeyTrustLine"),
      offer: xdr.lookup("LedgerKeyOffer"),
      data: xdr.lookup("LedgerKeyData"),
      claimableBalance: xdr.lookup("LedgerKeyClaimableBalance"),
      liquidityPool: xdr.lookup("LedgerKeyLiquidityPool"),
      contractData: xdr.lookup("LedgerKeyContractData"),
      contractCode: xdr.lookup("LedgerKeyContractCode"),
      configSetting: xdr.lookup("LedgerKeyConfigSetting"),
      ttl: xdr.lookup("LedgerKeyTtl")
    }
  });
  xdr.enum("EnvelopeType", {
    envelopeTypeTxV0: 0,
    envelopeTypeScp: 1,
    envelopeTypeTx: 2,
    envelopeTypeAuth: 3,
    envelopeTypeScpvalue: 4,
    envelopeTypeTxFeeBump: 5,
    envelopeTypeOpId: 6,
    envelopeTypePoolRevokeOpId: 7,
    envelopeTypeContractId: 8,
    envelopeTypeSorobanAuthorization: 9,
    envelopeTypeSorobanAuthorizationWithAddress: 10
  });
  xdr.enum("BucketListType", {
    live: 0,
    hotArchive: 1
  });
  xdr.enum("BucketEntryType", {
    metaentry: -1,
    liveentry: 0,
    deadentry: 1,
    initentry: 2
  });
  xdr.enum("HotArchiveBucketEntryType", {
    hotArchiveMetaentry: -1,
    hotArchiveArchived: 0,
    hotArchiveLive: 1
  });
  xdr.union("BucketMetadataExt", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [
      [0, xdr.void()],
      [1, "bucketListType"]
    ],
    arms: {
      bucketListType: xdr.lookup("BucketListType")
    }
  });
  xdr.struct("BucketMetadata", [
    ["ledgerVersion", xdr.lookup("Uint32")],
    ["ext", xdr.lookup("BucketMetadataExt")]
  ]);
  xdr.union("BucketEntry", {
    switchOn: xdr.lookup("BucketEntryType"),
    switchName: "type",
    switches: [
      ["liveentry", "liveEntry"],
      ["initentry", "liveEntry"],
      ["deadentry", "deadEntry"],
      ["metaentry", "metaEntry"]
    ],
    arms: {
      liveEntry: xdr.lookup("LedgerEntry"),
      deadEntry: xdr.lookup("LedgerKey"),
      metaEntry: xdr.lookup("BucketMetadata")
    }
  });
  xdr.union("HotArchiveBucketEntry", {
    switchOn: xdr.lookup("HotArchiveBucketEntryType"),
    switchName: "type",
    switches: [
      ["hotArchiveArchived", "archivedEntry"],
      ["hotArchiveLive", "key"],
      ["hotArchiveMetaentry", "metaEntry"]
    ],
    arms: {
      archivedEntry: xdr.lookup("LedgerEntry"),
      key: xdr.lookup("LedgerKey"),
      metaEntry: xdr.lookup("BucketMetadata")
    }
  });
  xdr.typedef("UpgradeType", xdr.varOpaque(128));
  xdr.enum("StellarValueType", {
    stellarValueBasic: 0,
    stellarValueSigned: 1
  });
  xdr.struct("LedgerCloseValueSignature", [
    ["nodeId", xdr.lookup("NodeId")],
    ["signature", xdr.lookup("Signature")]
  ]);
  xdr.union("StellarValueExt", {
    switchOn: xdr.lookup("StellarValueType"),
    switchName: "v",
    switches: [
      ["stellarValueBasic", xdr.void()],
      ["stellarValueSigned", "lcValueSignature"]
    ],
    arms: {
      lcValueSignature: xdr.lookup("LedgerCloseValueSignature")
    }
  });
  xdr.struct("StellarValue", [
    ["txSetHash", xdr.lookup("Hash")],
    ["closeTime", xdr.lookup("TimePoint")],
    ["upgrades", xdr.varArray(xdr.lookup("UpgradeType"), 6)],
    ["ext", xdr.lookup("StellarValueExt")]
  ]);
  xdr.const("MASK_LEDGER_HEADER_FLAGS", 7);
  xdr.enum("LedgerHeaderFlags", {
    disableLiquidityPoolTradingFlag: 1,
    disableLiquidityPoolDepositFlag: 2,
    disableLiquidityPoolWithdrawalFlag: 4
  });
  xdr.union("LedgerHeaderExtensionV1Ext", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [[0, xdr.void()]],
    arms: {}
  });
  xdr.struct("LedgerHeaderExtensionV1", [
    ["flags", xdr.lookup("Uint32")],
    ["ext", xdr.lookup("LedgerHeaderExtensionV1Ext")]
  ]);
  xdr.union("LedgerHeaderExt", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [
      [0, xdr.void()],
      [1, "v1"]
    ],
    arms: {
      v1: xdr.lookup("LedgerHeaderExtensionV1")
    }
  });
  xdr.struct("LedgerHeader", [
    ["ledgerVersion", xdr.lookup("Uint32")],
    ["previousLedgerHash", xdr.lookup("Hash")],
    ["scpValue", xdr.lookup("StellarValue")],
    ["txSetResultHash", xdr.lookup("Hash")],
    ["bucketListHash", xdr.lookup("Hash")],
    ["ledgerSeq", xdr.lookup("Uint32")],
    ["totalCoins", xdr.lookup("Int64")],
    ["feePool", xdr.lookup("Int64")],
    ["inflationSeq", xdr.lookup("Uint32")],
    ["idPool", xdr.lookup("Uint64")],
    ["baseFee", xdr.lookup("Uint32")],
    ["baseReserve", xdr.lookup("Uint32")],
    ["maxTxSetSize", xdr.lookup("Uint32")],
    ["skipList", xdr.array(xdr.lookup("Hash"), 4)],
    ["ext", xdr.lookup("LedgerHeaderExt")]
  ]);
  xdr.enum("LedgerUpgradeType", {
    ledgerUpgradeVersion: 1,
    ledgerUpgradeBaseFee: 2,
    ledgerUpgradeMaxTxSetSize: 3,
    ledgerUpgradeBaseReserve: 4,
    ledgerUpgradeFlags: 5,
    ledgerUpgradeConfig: 6,
    ledgerUpgradeMaxSorobanTxSetSize: 7
  });
  xdr.struct("ConfigUpgradeSetKey", [
    ["contractId", xdr.lookup("ContractId")],
    ["contentHash", xdr.lookup("Hash")]
  ]);
  xdr.union("LedgerUpgrade", {
    switchOn: xdr.lookup("LedgerUpgradeType"),
    switchName: "type",
    switches: [
      ["ledgerUpgradeVersion", "newLedgerVersion"],
      ["ledgerUpgradeBaseFee", "newBaseFee"],
      ["ledgerUpgradeMaxTxSetSize", "newMaxTxSetSize"],
      ["ledgerUpgradeBaseReserve", "newBaseReserve"],
      ["ledgerUpgradeFlags", "newFlags"],
      ["ledgerUpgradeConfig", "newConfig"],
      ["ledgerUpgradeMaxSorobanTxSetSize", "newMaxSorobanTxSetSize"]
    ],
    arms: {
      newLedgerVersion: xdr.lookup("Uint32"),
      newBaseFee: xdr.lookup("Uint32"),
      newMaxTxSetSize: xdr.lookup("Uint32"),
      newBaseReserve: xdr.lookup("Uint32"),
      newFlags: xdr.lookup("Uint32"),
      newConfig: xdr.lookup("ConfigUpgradeSetKey"),
      newMaxSorobanTxSetSize: xdr.lookup("Uint32")
    }
  });
  xdr.struct("ConfigUpgradeSet", [
    [
      "updatedEntry",
      xdr.varArray(xdr.lookup("ConfigSettingEntry"), 2147483647)
    ]
  ]);
  xdr.enum("TxSetComponentType", {
    txsetCompTxsMaybeDiscountedFee: 0
  });
  xdr.typedef(
    "DependentTxCluster",
    xdr.varArray(xdr.lookup("TransactionEnvelope"), 2147483647)
  );
  xdr.typedef(
    "ParallelTxExecutionStage",
    xdr.varArray(xdr.lookup("DependentTxCluster"), 2147483647)
  );
  xdr.struct("ParallelTxsComponent", [
    ["baseFee", xdr.option(xdr.lookup("Int64"))],
    [
      "executionStages",
      xdr.varArray(xdr.lookup("ParallelTxExecutionStage"), 2147483647)
    ]
  ]);
  xdr.struct("TxSetComponentTxsMaybeDiscountedFee", [
    ["baseFee", xdr.option(xdr.lookup("Int64"))],
    ["txes", xdr.varArray(xdr.lookup("TransactionEnvelope"), 2147483647)]
  ]);
  xdr.union("TxSetComponent", {
    switchOn: xdr.lookup("TxSetComponentType"),
    switchName: "type",
    switches: [["txsetCompTxsMaybeDiscountedFee", "txsMaybeDiscountedFee"]],
    arms: {
      txsMaybeDiscountedFee: xdr.lookup("TxSetComponentTxsMaybeDiscountedFee")
    }
  });
  xdr.union("TransactionPhase", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [
      [0, "v0Components"],
      [1, "parallelTxsComponent"]
    ],
    arms: {
      v0Components: xdr.varArray(xdr.lookup("TxSetComponent"), 2147483647),
      parallelTxsComponent: xdr.lookup("ParallelTxsComponent")
    }
  });
  xdr.struct("TransactionSet", [
    ["previousLedgerHash", xdr.lookup("Hash")],
    ["txes", xdr.varArray(xdr.lookup("TransactionEnvelope"), 2147483647)]
  ]);
  xdr.struct("TransactionSetV1", [
    ["previousLedgerHash", xdr.lookup("Hash")],
    ["phases", xdr.varArray(xdr.lookup("TransactionPhase"), 2147483647)]
  ]);
  xdr.union("GeneralizedTransactionSet", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [[1, "v1TxSet"]],
    arms: {
      v1TxSet: xdr.lookup("TransactionSetV1")
    }
  });
  xdr.struct("TransactionResultPair", [
    ["transactionHash", xdr.lookup("Hash")],
    ["result", xdr.lookup("TransactionResult")]
  ]);
  xdr.struct("TransactionResultSet", [
    ["results", xdr.varArray(xdr.lookup("TransactionResultPair"), 2147483647)]
  ]);
  xdr.union("TransactionHistoryEntryExt", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [
      [0, xdr.void()],
      [1, "generalizedTxSet"]
    ],
    arms: {
      generalizedTxSet: xdr.lookup("GeneralizedTransactionSet")
    }
  });
  xdr.struct("TransactionHistoryEntry", [
    ["ledgerSeq", xdr.lookup("Uint32")],
    ["txSet", xdr.lookup("TransactionSet")],
    ["ext", xdr.lookup("TransactionHistoryEntryExt")]
  ]);
  xdr.union("TransactionHistoryResultEntryExt", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [[0, xdr.void()]],
    arms: {}
  });
  xdr.struct("TransactionHistoryResultEntry", [
    ["ledgerSeq", xdr.lookup("Uint32")],
    ["txResultSet", xdr.lookup("TransactionResultSet")],
    ["ext", xdr.lookup("TransactionHistoryResultEntryExt")]
  ]);
  xdr.union("LedgerHeaderHistoryEntryExt", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [[0, xdr.void()]],
    arms: {}
  });
  xdr.struct("LedgerHeaderHistoryEntry", [
    ["hash", xdr.lookup("Hash")],
    ["header", xdr.lookup("LedgerHeader")],
    ["ext", xdr.lookup("LedgerHeaderHistoryEntryExt")]
  ]);
  xdr.struct("LedgerScpMessages", [
    ["ledgerSeq", xdr.lookup("Uint32")],
    ["messages", xdr.varArray(xdr.lookup("ScpEnvelope"), 2147483647)]
  ]);
  xdr.struct("ScpHistoryEntryV0", [
    ["quorumSets", xdr.varArray(xdr.lookup("ScpQuorumSet"), 2147483647)],
    ["ledgerMessages", xdr.lookup("LedgerScpMessages")]
  ]);
  xdr.union("ScpHistoryEntry", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [[0, "v0"]],
    arms: {
      v0: xdr.lookup("ScpHistoryEntryV0")
    }
  });
  xdr.enum("LedgerEntryChangeType", {
    ledgerEntryCreated: 0,
    ledgerEntryUpdated: 1,
    ledgerEntryRemoved: 2,
    ledgerEntryState: 3,
    ledgerEntryRestored: 4
  });
  xdr.union("LedgerEntryChange", {
    switchOn: xdr.lookup("LedgerEntryChangeType"),
    switchName: "type",
    switches: [
      ["ledgerEntryCreated", "created"],
      ["ledgerEntryUpdated", "updated"],
      ["ledgerEntryRemoved", "removed"],
      ["ledgerEntryState", "state"],
      ["ledgerEntryRestored", "restored"]
    ],
    arms: {
      created: xdr.lookup("LedgerEntry"),
      updated: xdr.lookup("LedgerEntry"),
      removed: xdr.lookup("LedgerKey"),
      state: xdr.lookup("LedgerEntry"),
      restored: xdr.lookup("LedgerEntry")
    }
  });
  xdr.typedef(
    "LedgerEntryChanges",
    xdr.varArray(xdr.lookup("LedgerEntryChange"), 2147483647)
  );
  xdr.struct("OperationMeta", [["changes", xdr.lookup("LedgerEntryChanges")]]);
  xdr.struct("TransactionMetaV1", [
    ["txChanges", xdr.lookup("LedgerEntryChanges")],
    ["operations", xdr.varArray(xdr.lookup("OperationMeta"), 2147483647)]
  ]);
  xdr.struct("TransactionMetaV2", [
    ["txChangesBefore", xdr.lookup("LedgerEntryChanges")],
    ["operations", xdr.varArray(xdr.lookup("OperationMeta"), 2147483647)],
    ["txChangesAfter", xdr.lookup("LedgerEntryChanges")]
  ]);
  xdr.enum("ContractEventType", {
    system: 0,
    contract: 1,
    diagnostic: 2
  });
  xdr.struct("ContractEventV0", [
    ["topics", xdr.varArray(xdr.lookup("ScVal"), 2147483647)],
    ["data", xdr.lookup("ScVal")]
  ]);
  xdr.union("ContractEventBody", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [[0, "v0"]],
    arms: {
      v0: xdr.lookup("ContractEventV0")
    }
  });
  xdr.struct("ContractEvent", [
    ["ext", xdr.lookup("ExtensionPoint")],
    ["contractId", xdr.option(xdr.lookup("ContractId"))],
    ["type", xdr.lookup("ContractEventType")],
    ["body", xdr.lookup("ContractEventBody")]
  ]);
  xdr.struct("DiagnosticEvent", [
    ["inSuccessfulContractCall", xdr.bool()],
    ["event", xdr.lookup("ContractEvent")]
  ]);
  xdr.struct("SorobanTransactionMetaExtV1", [
    ["ext", xdr.lookup("ExtensionPoint")],
    ["totalNonRefundableResourceFeeCharged", xdr.lookup("Int64")],
    ["totalRefundableResourceFeeCharged", xdr.lookup("Int64")],
    ["rentFeeCharged", xdr.lookup("Int64")]
  ]);
  xdr.union("SorobanTransactionMetaExt", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [
      [0, xdr.void()],
      [1, "v1"]
    ],
    arms: {
      v1: xdr.lookup("SorobanTransactionMetaExtV1")
    }
  });
  xdr.struct("SorobanTransactionMeta", [
    ["ext", xdr.lookup("SorobanTransactionMetaExt")],
    ["events", xdr.varArray(xdr.lookup("ContractEvent"), 2147483647)],
    ["returnValue", xdr.lookup("ScVal")],
    [
      "diagnosticEvents",
      xdr.varArray(xdr.lookup("DiagnosticEvent"), 2147483647)
    ]
  ]);
  xdr.struct("TransactionMetaV3", [
    ["ext", xdr.lookup("ExtensionPoint")],
    ["txChangesBefore", xdr.lookup("LedgerEntryChanges")],
    ["operations", xdr.varArray(xdr.lookup("OperationMeta"), 2147483647)],
    ["txChangesAfter", xdr.lookup("LedgerEntryChanges")],
    ["sorobanMeta", xdr.option(xdr.lookup("SorobanTransactionMeta"))]
  ]);
  xdr.struct("OperationMetaV2", [
    ["ext", xdr.lookup("ExtensionPoint")],
    ["changes", xdr.lookup("LedgerEntryChanges")],
    ["events", xdr.varArray(xdr.lookup("ContractEvent"), 2147483647)]
  ]);
  xdr.struct("SorobanTransactionMetaV2", [
    ["ext", xdr.lookup("SorobanTransactionMetaExt")],
    ["returnValue", xdr.option(xdr.lookup("ScVal"))]
  ]);
  xdr.enum("TransactionEventStage", {
    transactionEventStageBeforeAllTxes: 0,
    transactionEventStageAfterTx: 1,
    transactionEventStageAfterAllTxes: 2
  });
  xdr.struct("TransactionEvent", [
    ["stage", xdr.lookup("TransactionEventStage")],
    ["event", xdr.lookup("ContractEvent")]
  ]);
  xdr.struct("TransactionMetaV4", [
    ["ext", xdr.lookup("ExtensionPoint")],
    ["txChangesBefore", xdr.lookup("LedgerEntryChanges")],
    ["operations", xdr.varArray(xdr.lookup("OperationMetaV2"), 2147483647)],
    ["txChangesAfter", xdr.lookup("LedgerEntryChanges")],
    ["sorobanMeta", xdr.option(xdr.lookup("SorobanTransactionMetaV2"))],
    ["events", xdr.varArray(xdr.lookup("TransactionEvent"), 2147483647)],
    [
      "diagnosticEvents",
      xdr.varArray(xdr.lookup("DiagnosticEvent"), 2147483647)
    ]
  ]);
  xdr.struct("InvokeHostFunctionSuccessPreImage", [
    ["returnValue", xdr.lookup("ScVal")],
    ["events", xdr.varArray(xdr.lookup("ContractEvent"), 2147483647)]
  ]);
  xdr.union("TransactionMeta", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [
      [0, "operations"],
      [1, "v1"],
      [2, "v2"],
      [3, "v3"],
      [4, "v4"]
    ],
    arms: {
      operations: xdr.varArray(xdr.lookup("OperationMeta"), 2147483647),
      v1: xdr.lookup("TransactionMetaV1"),
      v2: xdr.lookup("TransactionMetaV2"),
      v3: xdr.lookup("TransactionMetaV3"),
      v4: xdr.lookup("TransactionMetaV4")
    }
  });
  xdr.struct("TransactionResultMeta", [
    ["result", xdr.lookup("TransactionResultPair")],
    ["feeProcessing", xdr.lookup("LedgerEntryChanges")],
    ["txApplyProcessing", xdr.lookup("TransactionMeta")]
  ]);
  xdr.struct("TransactionResultMetaV1", [
    ["ext", xdr.lookup("ExtensionPoint")],
    ["result", xdr.lookup("TransactionResultPair")],
    ["feeProcessing", xdr.lookup("LedgerEntryChanges")],
    ["txApplyProcessing", xdr.lookup("TransactionMeta")],
    ["postTxApplyFeeProcessing", xdr.lookup("LedgerEntryChanges")]
  ]);
  xdr.struct("UpgradeEntryMeta", [
    ["upgrade", xdr.lookup("LedgerUpgrade")],
    ["changes", xdr.lookup("LedgerEntryChanges")]
  ]);
  xdr.struct("LedgerCloseMetaV0", [
    ["ledgerHeader", xdr.lookup("LedgerHeaderHistoryEntry")],
    ["txSet", xdr.lookup("TransactionSet")],
    [
      "txProcessing",
      xdr.varArray(xdr.lookup("TransactionResultMeta"), 2147483647)
    ],
    [
      "upgradesProcessing",
      xdr.varArray(xdr.lookup("UpgradeEntryMeta"), 2147483647)
    ],
    ["scpInfo", xdr.varArray(xdr.lookup("ScpHistoryEntry"), 2147483647)]
  ]);
  xdr.struct("LedgerCloseMetaExtV1", [
    ["ext", xdr.lookup("ExtensionPoint")],
    ["sorobanFeeWrite1Kb", xdr.lookup("Int64")]
  ]);
  xdr.union("LedgerCloseMetaExt", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [
      [0, xdr.void()],
      [1, "v1"]
    ],
    arms: {
      v1: xdr.lookup("LedgerCloseMetaExtV1")
    }
  });
  xdr.struct("LedgerCloseMetaV1", [
    ["ext", xdr.lookup("LedgerCloseMetaExt")],
    ["ledgerHeader", xdr.lookup("LedgerHeaderHistoryEntry")],
    ["txSet", xdr.lookup("GeneralizedTransactionSet")],
    [
      "txProcessing",
      xdr.varArray(xdr.lookup("TransactionResultMeta"), 2147483647)
    ],
    [
      "upgradesProcessing",
      xdr.varArray(xdr.lookup("UpgradeEntryMeta"), 2147483647)
    ],
    ["scpInfo", xdr.varArray(xdr.lookup("ScpHistoryEntry"), 2147483647)],
    ["totalByteSizeOfLiveSorobanState", xdr.lookup("Uint64")],
    ["evictedKeys", xdr.varArray(xdr.lookup("LedgerKey"), 2147483647)],
    ["unused", xdr.varArray(xdr.lookup("LedgerEntry"), 2147483647)]
  ]);
  xdr.struct("LedgerCloseMetaV2", [
    ["ext", xdr.lookup("LedgerCloseMetaExt")],
    ["ledgerHeader", xdr.lookup("LedgerHeaderHistoryEntry")],
    ["txSet", xdr.lookup("GeneralizedTransactionSet")],
    [
      "txProcessing",
      xdr.varArray(xdr.lookup("TransactionResultMetaV1"), 2147483647)
    ],
    [
      "upgradesProcessing",
      xdr.varArray(xdr.lookup("UpgradeEntryMeta"), 2147483647)
    ],
    ["scpInfo", xdr.varArray(xdr.lookup("ScpHistoryEntry"), 2147483647)],
    ["totalByteSizeOfLiveSorobanState", xdr.lookup("Uint64")],
    ["evictedKeys", xdr.varArray(xdr.lookup("LedgerKey"), 2147483647)]
  ]);
  xdr.union("LedgerCloseMeta", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [
      [0, "v0"],
      [1, "v1"],
      [2, "v2"]
    ],
    arms: {
      v0: xdr.lookup("LedgerCloseMetaV0"),
      v1: xdr.lookup("LedgerCloseMetaV1"),
      v2: xdr.lookup("LedgerCloseMetaV2")
    }
  });
  xdr.enum("ErrorCode", {
    errMisc: 0,
    errData: 1,
    errConf: 2,
    errAuth: 3,
    errLoad: 4
  });
  xdr.struct("Error", [
    ["code", xdr.lookup("ErrorCode")],
    ["msg", xdr.string(100)]
  ]);
  xdr.struct("SendMore", [["numMessages", xdr.lookup("Uint32")]]);
  xdr.struct("SendMoreExtended", [
    ["numMessages", xdr.lookup("Uint32")],
    ["numBytes", xdr.lookup("Uint32")]
  ]);
  xdr.struct("AuthCert", [
    ["pubkey", xdr.lookup("Curve25519Public")],
    ["expiration", xdr.lookup("Uint64")],
    ["sig", xdr.lookup("Signature")]
  ]);
  xdr.struct("Hello", [
    ["ledgerVersion", xdr.lookup("Uint32")],
    ["overlayVersion", xdr.lookup("Uint32")],
    ["overlayMinVersion", xdr.lookup("Uint32")],
    ["networkId", xdr.lookup("Hash")],
    ["versionStr", xdr.string(100)],
    ["listeningPort", xdr.int()],
    ["peerId", xdr.lookup("NodeId")],
    ["cert", xdr.lookup("AuthCert")],
    ["nonce", xdr.lookup("Uint256")]
  ]);
  xdr.const("AUTH_MSG_FLAG_FLOW_CONTROL_BYTES_REQUESTED", 200);
  xdr.struct("Auth", [["flags", xdr.int()]]);
  xdr.enum("IpAddrType", {
    iPv4: 0,
    iPv6: 1
  });
  xdr.union("PeerAddressIp", {
    switchOn: xdr.lookup("IpAddrType"),
    switchName: "type",
    switches: [
      ["iPv4", "ipv4"],
      ["iPv6", "ipv6"]
    ],
    arms: {
      ipv4: xdr.opaque(4),
      ipv6: xdr.opaque(16)
    }
  });
  xdr.struct("PeerAddress", [
    ["ip", xdr.lookup("PeerAddressIp")],
    ["port", xdr.lookup("Uint32")],
    ["numFailures", xdr.lookup("Uint32")]
  ]);
  xdr.enum("MessageType", {
    errorMsg: 0,
    auth: 2,
    dontHave: 3,
    peers: 5,
    getTxSet: 6,
    txSet: 7,
    generalizedTxSet: 17,
    transaction: 8,
    getScpQuorumset: 9,
    scpQuorumset: 10,
    scpMessage: 11,
    getScpState: 12,
    hello: 13,
    sendMore: 16,
    sendMoreExtended: 20,
    floodAdvert: 18,
    floodDemand: 19,
    timeSlicedSurveyRequest: 21,
    timeSlicedSurveyResponse: 22,
    timeSlicedSurveyStartCollecting: 23,
    timeSlicedSurveyStopCollecting: 24
  });
  xdr.struct("DontHave", [
    ["type", xdr.lookup("MessageType")],
    ["reqHash", xdr.lookup("Uint256")]
  ]);
  xdr.enum("SurveyMessageCommandType", {
    timeSlicedSurveyTopology: 1
  });
  xdr.enum("SurveyMessageResponseType", {
    surveyTopologyResponseV2: 2
  });
  xdr.struct("TimeSlicedSurveyStartCollectingMessage", [
    ["surveyorId", xdr.lookup("NodeId")],
    ["nonce", xdr.lookup("Uint32")],
    ["ledgerNum", xdr.lookup("Uint32")]
  ]);
  xdr.struct("SignedTimeSlicedSurveyStartCollectingMessage", [
    ["signature", xdr.lookup("Signature")],
    ["startCollecting", xdr.lookup("TimeSlicedSurveyStartCollectingMessage")]
  ]);
  xdr.struct("TimeSlicedSurveyStopCollectingMessage", [
    ["surveyorId", xdr.lookup("NodeId")],
    ["nonce", xdr.lookup("Uint32")],
    ["ledgerNum", xdr.lookup("Uint32")]
  ]);
  xdr.struct("SignedTimeSlicedSurveyStopCollectingMessage", [
    ["signature", xdr.lookup("Signature")],
    ["stopCollecting", xdr.lookup("TimeSlicedSurveyStopCollectingMessage")]
  ]);
  xdr.struct("SurveyRequestMessage", [
    ["surveyorPeerId", xdr.lookup("NodeId")],
    ["surveyedPeerId", xdr.lookup("NodeId")],
    ["ledgerNum", xdr.lookup("Uint32")],
    ["encryptionKey", xdr.lookup("Curve25519Public")],
    ["commandType", xdr.lookup("SurveyMessageCommandType")]
  ]);
  xdr.struct("TimeSlicedSurveyRequestMessage", [
    ["request", xdr.lookup("SurveyRequestMessage")],
    ["nonce", xdr.lookup("Uint32")],
    ["inboundPeersIndex", xdr.lookup("Uint32")],
    ["outboundPeersIndex", xdr.lookup("Uint32")]
  ]);
  xdr.struct("SignedTimeSlicedSurveyRequestMessage", [
    ["requestSignature", xdr.lookup("Signature")],
    ["request", xdr.lookup("TimeSlicedSurveyRequestMessage")]
  ]);
  xdr.typedef("EncryptedBody", xdr.varOpaque(64e3));
  xdr.struct("SurveyResponseMessage", [
    ["surveyorPeerId", xdr.lookup("NodeId")],
    ["surveyedPeerId", xdr.lookup("NodeId")],
    ["ledgerNum", xdr.lookup("Uint32")],
    ["commandType", xdr.lookup("SurveyMessageCommandType")],
    ["encryptedBody", xdr.lookup("EncryptedBody")]
  ]);
  xdr.struct("TimeSlicedSurveyResponseMessage", [
    ["response", xdr.lookup("SurveyResponseMessage")],
    ["nonce", xdr.lookup("Uint32")]
  ]);
  xdr.struct("SignedTimeSlicedSurveyResponseMessage", [
    ["responseSignature", xdr.lookup("Signature")],
    ["response", xdr.lookup("TimeSlicedSurveyResponseMessage")]
  ]);
  xdr.struct("PeerStats", [
    ["id", xdr.lookup("NodeId")],
    ["versionStr", xdr.string(100)],
    ["messagesRead", xdr.lookup("Uint64")],
    ["messagesWritten", xdr.lookup("Uint64")],
    ["bytesRead", xdr.lookup("Uint64")],
    ["bytesWritten", xdr.lookup("Uint64")],
    ["secondsConnected", xdr.lookup("Uint64")],
    ["uniqueFloodBytesRecv", xdr.lookup("Uint64")],
    ["duplicateFloodBytesRecv", xdr.lookup("Uint64")],
    ["uniqueFetchBytesRecv", xdr.lookup("Uint64")],
    ["duplicateFetchBytesRecv", xdr.lookup("Uint64")],
    ["uniqueFloodMessageRecv", xdr.lookup("Uint64")],
    ["duplicateFloodMessageRecv", xdr.lookup("Uint64")],
    ["uniqueFetchMessageRecv", xdr.lookup("Uint64")],
    ["duplicateFetchMessageRecv", xdr.lookup("Uint64")]
  ]);
  xdr.struct("TimeSlicedNodeData", [
    ["addedAuthenticatedPeers", xdr.lookup("Uint32")],
    ["droppedAuthenticatedPeers", xdr.lookup("Uint32")],
    ["totalInboundPeerCount", xdr.lookup("Uint32")],
    ["totalOutboundPeerCount", xdr.lookup("Uint32")],
    ["p75ScpFirstToSelfLatencyMs", xdr.lookup("Uint32")],
    ["p75ScpSelfToOtherLatencyMs", xdr.lookup("Uint32")],
    ["lostSyncCount", xdr.lookup("Uint32")],
    ["isValidator", xdr.bool()],
    ["maxInboundPeerCount", xdr.lookup("Uint32")],
    ["maxOutboundPeerCount", xdr.lookup("Uint32")]
  ]);
  xdr.struct("TimeSlicedPeerData", [
    ["peerStats", xdr.lookup("PeerStats")],
    ["averageLatencyMs", xdr.lookup("Uint32")]
  ]);
  xdr.typedef(
    "TimeSlicedPeerDataList",
    xdr.varArray(xdr.lookup("TimeSlicedPeerData"), 25)
  );
  xdr.struct("TopologyResponseBodyV2", [
    ["inboundPeers", xdr.lookup("TimeSlicedPeerDataList")],
    ["outboundPeers", xdr.lookup("TimeSlicedPeerDataList")],
    ["nodeData", xdr.lookup("TimeSlicedNodeData")]
  ]);
  xdr.union("SurveyResponseBody", {
    switchOn: xdr.lookup("SurveyMessageResponseType"),
    switchName: "type",
    switches: [["surveyTopologyResponseV2", "topologyResponseBodyV2"]],
    arms: {
      topologyResponseBodyV2: xdr.lookup("TopologyResponseBodyV2")
    }
  });
  xdr.const("TX_ADVERT_VECTOR_MAX_SIZE", 1e3);
  xdr.typedef(
    "TxAdvertVector",
    xdr.varArray(xdr.lookup("Hash"), xdr.lookup("TX_ADVERT_VECTOR_MAX_SIZE"))
  );
  xdr.struct("FloodAdvert", [["txHashes", xdr.lookup("TxAdvertVector")]]);
  xdr.const("TX_DEMAND_VECTOR_MAX_SIZE", 1e3);
  xdr.typedef(
    "TxDemandVector",
    xdr.varArray(xdr.lookup("Hash"), xdr.lookup("TX_DEMAND_VECTOR_MAX_SIZE"))
  );
  xdr.struct("FloodDemand", [["txHashes", xdr.lookup("TxDemandVector")]]);
  xdr.union("StellarMessage", {
    switchOn: xdr.lookup("MessageType"),
    switchName: "type",
    switches: [
      ["errorMsg", "error"],
      ["hello", "hello"],
      ["auth", "auth"],
      ["dontHave", "dontHave"],
      ["peers", "peers"],
      ["getTxSet", "txSetHash"],
      ["txSet", "txSet"],
      ["generalizedTxSet", "generalizedTxSet"],
      ["transaction", "transaction"],
      ["timeSlicedSurveyRequest", "signedTimeSlicedSurveyRequestMessage"],
      ["timeSlicedSurveyResponse", "signedTimeSlicedSurveyResponseMessage"],
      [
        "timeSlicedSurveyStartCollecting",
        "signedTimeSlicedSurveyStartCollectingMessage"
      ],
      [
        "timeSlicedSurveyStopCollecting",
        "signedTimeSlicedSurveyStopCollectingMessage"
      ],
      ["getScpQuorumset", "qSetHash"],
      ["scpQuorumset", "qSet"],
      ["scpMessage", "envelope"],
      ["getScpState", "getScpLedgerSeq"],
      ["sendMore", "sendMoreMessage"],
      ["sendMoreExtended", "sendMoreExtendedMessage"],
      ["floodAdvert", "floodAdvert"],
      ["floodDemand", "floodDemand"]
    ],
    arms: {
      error: xdr.lookup("Error"),
      hello: xdr.lookup("Hello"),
      auth: xdr.lookup("Auth"),
      dontHave: xdr.lookup("DontHave"),
      peers: xdr.varArray(xdr.lookup("PeerAddress"), 100),
      txSetHash: xdr.lookup("Uint256"),
      txSet: xdr.lookup("TransactionSet"),
      generalizedTxSet: xdr.lookup("GeneralizedTransactionSet"),
      transaction: xdr.lookup("TransactionEnvelope"),
      signedTimeSlicedSurveyRequestMessage: xdr.lookup(
        "SignedTimeSlicedSurveyRequestMessage"
      ),
      signedTimeSlicedSurveyResponseMessage: xdr.lookup(
        "SignedTimeSlicedSurveyResponseMessage"
      ),
      signedTimeSlicedSurveyStartCollectingMessage: xdr.lookup(
        "SignedTimeSlicedSurveyStartCollectingMessage"
      ),
      signedTimeSlicedSurveyStopCollectingMessage: xdr.lookup(
        "SignedTimeSlicedSurveyStopCollectingMessage"
      ),
      qSetHash: xdr.lookup("Uint256"),
      qSet: xdr.lookup("ScpQuorumSet"),
      envelope: xdr.lookup("ScpEnvelope"),
      getScpLedgerSeq: xdr.lookup("Uint32"),
      sendMoreMessage: xdr.lookup("SendMore"),
      sendMoreExtendedMessage: xdr.lookup("SendMoreExtended"),
      floodAdvert: xdr.lookup("FloodAdvert"),
      floodDemand: xdr.lookup("FloodDemand")
    }
  });
  xdr.struct("AuthenticatedMessageV0", [
    ["sequence", xdr.lookup("Uint64")],
    ["message", xdr.lookup("StellarMessage")],
    ["mac", xdr.lookup("HmacSha256Mac")]
  ]);
  xdr.union("AuthenticatedMessage", {
    switchOn: xdr.lookup("Uint32"),
    switchName: "v",
    switches: [[0, "v0"]],
    arms: {
      v0: xdr.lookup("AuthenticatedMessageV0")
    }
  });
  xdr.const("MAX_OPS_PER_TX", 100);
  xdr.union("LiquidityPoolParameters", {
    switchOn: xdr.lookup("LiquidityPoolType"),
    switchName: "type",
    switches: [["liquidityPoolConstantProduct", "constantProduct"]],
    arms: {
      constantProduct: xdr.lookup("LiquidityPoolConstantProductParameters")
    }
  });
  xdr.struct("MuxedAccountMed25519", [
    ["id", xdr.lookup("Uint64")],
    ["ed25519", xdr.lookup("Uint256")]
  ]);
  xdr.union("MuxedAccount", {
    switchOn: xdr.lookup("CryptoKeyType"),
    switchName: "type",
    switches: [
      ["keyTypeEd25519", "ed25519"],
      ["keyTypeMuxedEd25519", "med25519"]
    ],
    arms: {
      ed25519: xdr.lookup("Uint256"),
      med25519: xdr.lookup("MuxedAccountMed25519")
    }
  });
  xdr.struct("DecoratedSignature", [
    ["hint", xdr.lookup("SignatureHint")],
    ["signature", xdr.lookup("Signature")]
  ]);
  xdr.enum("OperationType", {
    createAccount: 0,
    payment: 1,
    pathPaymentStrictReceive: 2,
    manageSellOffer: 3,
    createPassiveSellOffer: 4,
    setOptions: 5,
    changeTrust: 6,
    allowTrust: 7,
    accountMerge: 8,
    inflation: 9,
    manageData: 10,
    bumpSequence: 11,
    manageBuyOffer: 12,
    pathPaymentStrictSend: 13,
    createClaimableBalance: 14,
    claimClaimableBalance: 15,
    beginSponsoringFutureReserves: 16,
    endSponsoringFutureReserves: 17,
    revokeSponsorship: 18,
    clawback: 19,
    clawbackClaimableBalance: 20,
    setTrustLineFlags: 21,
    liquidityPoolDeposit: 22,
    liquidityPoolWithdraw: 23,
    invokeHostFunction: 24,
    extendFootprintTtl: 25,
    restoreFootprint: 26
  });
  xdr.struct("CreateAccountOp", [
    ["destination", xdr.lookup("AccountId")],
    ["startingBalance", xdr.lookup("Int64")]
  ]);
  xdr.struct("PaymentOp", [
    ["destination", xdr.lookup("MuxedAccount")],
    ["asset", xdr.lookup("Asset")],
    ["amount", xdr.lookup("Int64")]
  ]);
  xdr.struct("PathPaymentStrictReceiveOp", [
    ["sendAsset", xdr.lookup("Asset")],
    ["sendMax", xdr.lookup("Int64")],
    ["destination", xdr.lookup("MuxedAccount")],
    ["destAsset", xdr.lookup("Asset")],
    ["destAmount", xdr.lookup("Int64")],
    ["path", xdr.varArray(xdr.lookup("Asset"), 5)]
  ]);
  xdr.struct("PathPaymentStrictSendOp", [
    ["sendAsset", xdr.lookup("Asset")],
    ["sendAmount", xdr.lookup("Int64")],
    ["destination", xdr.lookup("MuxedAccount")],
    ["destAsset", xdr.lookup("Asset")],
    ["destMin", xdr.lookup("Int64")],
    ["path", xdr.varArray(xdr.lookup("Asset"), 5)]
  ]);
  xdr.struct("ManageSellOfferOp", [
    ["selling", xdr.lookup("Asset")],
    ["buying", xdr.lookup("Asset")],
    ["amount", xdr.lookup("Int64")],
    ["price", xdr.lookup("Price")],
    ["offerId", xdr.lookup("Int64")]
  ]);
  xdr.struct("ManageBuyOfferOp", [
    ["selling", xdr.lookup("Asset")],
    ["buying", xdr.lookup("Asset")],
    ["buyAmount", xdr.lookup("Int64")],
    ["price", xdr.lookup("Price")],
    ["offerId", xdr.lookup("Int64")]
  ]);
  xdr.struct("CreatePassiveSellOfferOp", [
    ["selling", xdr.lookup("Asset")],
    ["buying", xdr.lookup("Asset")],
    ["amount", xdr.lookup("Int64")],
    ["price", xdr.lookup("Price")]
  ]);
  xdr.struct("SetOptionsOp", [
    ["inflationDest", xdr.option(xdr.lookup("AccountId"))],
    ["clearFlags", xdr.option(xdr.lookup("Uint32"))],
    ["setFlags", xdr.option(xdr.lookup("Uint32"))],
    ["masterWeight", xdr.option(xdr.lookup("Uint32"))],
    ["lowThreshold", xdr.option(xdr.lookup("Uint32"))],
    ["medThreshold", xdr.option(xdr.lookup("Uint32"))],
    ["highThreshold", xdr.option(xdr.lookup("Uint32"))],
    ["homeDomain", xdr.option(xdr.lookup("String32"))],
    ["signer", xdr.option(xdr.lookup("Signer"))]
  ]);
  xdr.union("ChangeTrustAsset", {
    switchOn: xdr.lookup("AssetType"),
    switchName: "type",
    switches: [
      ["assetTypeNative", xdr.void()],
      ["assetTypeCreditAlphanum4", "alphaNum4"],
      ["assetTypeCreditAlphanum12", "alphaNum12"],
      ["assetTypePoolShare", "liquidityPool"]
    ],
    arms: {
      alphaNum4: xdr.lookup("AlphaNum4"),
      alphaNum12: xdr.lookup("AlphaNum12"),
      liquidityPool: xdr.lookup("LiquidityPoolParameters")
    }
  });
  xdr.struct("ChangeTrustOp", [
    ["line", xdr.lookup("ChangeTrustAsset")],
    ["limit", xdr.lookup("Int64")]
  ]);
  xdr.struct("AllowTrustOp", [
    ["trustor", xdr.lookup("AccountId")],
    ["asset", xdr.lookup("AssetCode")],
    ["authorize", xdr.lookup("Uint32")]
  ]);
  xdr.struct("ManageDataOp", [
    ["dataName", xdr.lookup("String64")],
    ["dataValue", xdr.option(xdr.lookup("DataValue"))]
  ]);
  xdr.struct("BumpSequenceOp", [["bumpTo", xdr.lookup("SequenceNumber")]]);
  xdr.struct("CreateClaimableBalanceOp", [
    ["asset", xdr.lookup("Asset")],
    ["amount", xdr.lookup("Int64")],
    ["claimants", xdr.varArray(xdr.lookup("Claimant"), 10)]
  ]);
  xdr.struct("ClaimClaimableBalanceOp", [
    ["balanceId", xdr.lookup("ClaimableBalanceId")]
  ]);
  xdr.struct("BeginSponsoringFutureReservesOp", [
    ["sponsoredId", xdr.lookup("AccountId")]
  ]);
  xdr.enum("RevokeSponsorshipType", {
    revokeSponsorshipLedgerEntry: 0,
    revokeSponsorshipSigner: 1
  });
  xdr.struct("RevokeSponsorshipOpSigner", [
    ["accountId", xdr.lookup("AccountId")],
    ["signerKey", xdr.lookup("SignerKey")]
  ]);
  xdr.union("RevokeSponsorshipOp", {
    switchOn: xdr.lookup("RevokeSponsorshipType"),
    switchName: "type",
    switches: [
      ["revokeSponsorshipLedgerEntry", "ledgerKey"],
      ["revokeSponsorshipSigner", "signer"]
    ],
    arms: {
      ledgerKey: xdr.lookup("LedgerKey"),
      signer: xdr.lookup("RevokeSponsorshipOpSigner")
    }
  });
  xdr.struct("ClawbackOp", [
    ["asset", xdr.lookup("Asset")],
    ["from", xdr.lookup("MuxedAccount")],
    ["amount", xdr.lookup("Int64")]
  ]);
  xdr.struct("ClawbackClaimableBalanceOp", [
    ["balanceId", xdr.lookup("ClaimableBalanceId")]
  ]);
  xdr.struct("SetTrustLineFlagsOp", [
    ["trustor", xdr.lookup("AccountId")],
    ["asset", xdr.lookup("Asset")],
    ["clearFlags", xdr.lookup("Uint32")],
    ["setFlags", xdr.lookup("Uint32")]
  ]);
  xdr.const("LIQUIDITY_POOL_FEE_V18", 30);
  xdr.struct("LiquidityPoolDepositOp", [
    ["liquidityPoolId", xdr.lookup("PoolId")],
    ["maxAmountA", xdr.lookup("Int64")],
    ["maxAmountB", xdr.lookup("Int64")],
    ["minPrice", xdr.lookup("Price")],
    ["maxPrice", xdr.lookup("Price")]
  ]);
  xdr.struct("LiquidityPoolWithdrawOp", [
    ["liquidityPoolId", xdr.lookup("PoolId")],
    ["amount", xdr.lookup("Int64")],
    ["minAmountA", xdr.lookup("Int64")],
    ["minAmountB", xdr.lookup("Int64")]
  ]);
  xdr.enum("HostFunctionType", {
    hostFunctionTypeInvokeContract: 0,
    hostFunctionTypeCreateContract: 1,
    hostFunctionTypeUploadContractWasm: 2,
    hostFunctionTypeCreateContractV2: 3
  });
  xdr.enum("ContractIdPreimageType", {
    contractIdPreimageFromAddress: 0,
    contractIdPreimageFromAsset: 1
  });
  xdr.struct("ContractIdPreimageFromAddress", [
    ["address", xdr.lookup("ScAddress")],
    ["salt", xdr.lookup("Uint256")]
  ]);
  xdr.union("ContractIdPreimage", {
    switchOn: xdr.lookup("ContractIdPreimageType"),
    switchName: "type",
    switches: [
      ["contractIdPreimageFromAddress", "fromAddress"],
      ["contractIdPreimageFromAsset", "fromAsset"]
    ],
    arms: {
      fromAddress: xdr.lookup("ContractIdPreimageFromAddress"),
      fromAsset: xdr.lookup("Asset")
    }
  });
  xdr.struct("CreateContractArgs", [
    ["contractIdPreimage", xdr.lookup("ContractIdPreimage")],
    ["executable", xdr.lookup("ContractExecutable")]
  ]);
  xdr.struct("CreateContractArgsV2", [
    ["contractIdPreimage", xdr.lookup("ContractIdPreimage")],
    ["executable", xdr.lookup("ContractExecutable")],
    ["constructorArgs", xdr.varArray(xdr.lookup("ScVal"), 2147483647)]
  ]);
  xdr.struct("InvokeContractArgs", [
    ["contractAddress", xdr.lookup("ScAddress")],
    ["functionName", xdr.lookup("ScSymbol")],
    ["args", xdr.varArray(xdr.lookup("ScVal"), 2147483647)]
  ]);
  xdr.union("HostFunction", {
    switchOn: xdr.lookup("HostFunctionType"),
    switchName: "type",
    switches: [
      ["hostFunctionTypeInvokeContract", "invokeContract"],
      ["hostFunctionTypeCreateContract", "createContract"],
      ["hostFunctionTypeUploadContractWasm", "wasm"],
      ["hostFunctionTypeCreateContractV2", "createContractV2"]
    ],
    arms: {
      invokeContract: xdr.lookup("InvokeContractArgs"),
      createContract: xdr.lookup("CreateContractArgs"),
      wasm: xdr.varOpaque(),
      createContractV2: xdr.lookup("CreateContractArgsV2")
    }
  });
  xdr.enum("SorobanAuthorizedFunctionType", {
    sorobanAuthorizedFunctionTypeContractFn: 0,
    sorobanAuthorizedFunctionTypeCreateContractHostFn: 1,
    sorobanAuthorizedFunctionTypeCreateContractV2HostFn: 2
  });
  xdr.union("SorobanAuthorizedFunction", {
    switchOn: xdr.lookup("SorobanAuthorizedFunctionType"),
    switchName: "type",
    switches: [
      ["sorobanAuthorizedFunctionTypeContractFn", "contractFn"],
      [
        "sorobanAuthorizedFunctionTypeCreateContractHostFn",
        "createContractHostFn"
      ],
      [
        "sorobanAuthorizedFunctionTypeCreateContractV2HostFn",
        "createContractV2HostFn"
      ]
    ],
    arms: {
      contractFn: xdr.lookup("InvokeContractArgs"),
      createContractHostFn: xdr.lookup("CreateContractArgs"),
      createContractV2HostFn: xdr.lookup("CreateContractArgsV2")
    }
  });
  xdr.struct("SorobanAuthorizedInvocation", [
    ["function", xdr.lookup("SorobanAuthorizedFunction")],
    [
      "subInvocations",
      xdr.varArray(xdr.lookup("SorobanAuthorizedInvocation"), 2147483647)
    ]
  ]);
  xdr.struct("SorobanAddressCredentials", [
    ["address", xdr.lookup("ScAddress")],
    ["nonce", xdr.lookup("Int64")],
    ["signatureExpirationLedger", xdr.lookup("Uint32")],
    ["signature", xdr.lookup("ScVal")]
  ]);
  xdr.struct("SorobanDelegateSignature", [
    ["address", xdr.lookup("ScAddress")],
    ["signature", xdr.lookup("ScVal")],
    [
      "nestedDelegates",
      xdr.varArray(xdr.lookup("SorobanDelegateSignature"), 2147483647)
    ]
  ]);
  xdr.struct("SorobanAddressCredentialsWithDelegates", [
    ["addressCredentials", xdr.lookup("SorobanAddressCredentials")],
    [
      "delegates",
      xdr.varArray(xdr.lookup("SorobanDelegateSignature"), 2147483647)
    ]
  ]);
  xdr.enum("SorobanCredentialsType", {
    sorobanCredentialsSourceAccount: 0,
    sorobanCredentialsAddress: 1,
    sorobanCredentialsAddressV2: 2,
    sorobanCredentialsAddressWithDelegates: 3
  });
  xdr.union("SorobanCredentials", {
    switchOn: xdr.lookup("SorobanCredentialsType"),
    switchName: "type",
    switches: [
      ["sorobanCredentialsSourceAccount", xdr.void()],
      ["sorobanCredentialsAddress", "address"],
      ["sorobanCredentialsAddressV2", "addressV2"],
      ["sorobanCredentialsAddressWithDelegates", "addressWithDelegates"]
    ],
    arms: {
      address: xdr.lookup("SorobanAddressCredentials"),
      addressV2: xdr.lookup("SorobanAddressCredentials"),
      addressWithDelegates: xdr.lookup(
        "SorobanAddressCredentialsWithDelegates"
      )
    }
  });
  xdr.struct("SorobanAuthorizationEntry", [
    ["credentials", xdr.lookup("SorobanCredentials")],
    ["rootInvocation", xdr.lookup("SorobanAuthorizedInvocation")]
  ]);
  xdr.typedef(
    "SorobanAuthorizationEntries",
    xdr.varArray(xdr.lookup("SorobanAuthorizationEntry"), 2147483647)
  );
  xdr.struct("InvokeHostFunctionOp", [
    ["hostFunction", xdr.lookup("HostFunction")],
    ["auth", xdr.varArray(xdr.lookup("SorobanAuthorizationEntry"), 2147483647)]
  ]);
  xdr.struct("ExtendFootprintTtlOp", [
    ["ext", xdr.lookup("ExtensionPoint")],
    ["extendTo", xdr.lookup("Uint32")]
  ]);
  xdr.struct("RestoreFootprintOp", [["ext", xdr.lookup("ExtensionPoint")]]);
  xdr.union("OperationBody", {
    switchOn: xdr.lookup("OperationType"),
    switchName: "type",
    switches: [
      ["createAccount", "createAccountOp"],
      ["payment", "paymentOp"],
      ["pathPaymentStrictReceive", "pathPaymentStrictReceiveOp"],
      ["manageSellOffer", "manageSellOfferOp"],
      ["createPassiveSellOffer", "createPassiveSellOfferOp"],
      ["setOptions", "setOptionsOp"],
      ["changeTrust", "changeTrustOp"],
      ["allowTrust", "allowTrustOp"],
      ["accountMerge", "destination"],
      ["inflation", xdr.void()],
      ["manageData", "manageDataOp"],
      ["bumpSequence", "bumpSequenceOp"],
      ["manageBuyOffer", "manageBuyOfferOp"],
      ["pathPaymentStrictSend", "pathPaymentStrictSendOp"],
      ["createClaimableBalance", "createClaimableBalanceOp"],
      ["claimClaimableBalance", "claimClaimableBalanceOp"],
      ["beginSponsoringFutureReserves", "beginSponsoringFutureReservesOp"],
      ["endSponsoringFutureReserves", xdr.void()],
      ["revokeSponsorship", "revokeSponsorshipOp"],
      ["clawback", "clawbackOp"],
      ["clawbackClaimableBalance", "clawbackClaimableBalanceOp"],
      ["setTrustLineFlags", "setTrustLineFlagsOp"],
      ["liquidityPoolDeposit", "liquidityPoolDepositOp"],
      ["liquidityPoolWithdraw", "liquidityPoolWithdrawOp"],
      ["invokeHostFunction", "invokeHostFunctionOp"],
      ["extendFootprintTtl", "extendFootprintTtlOp"],
      ["restoreFootprint", "restoreFootprintOp"]
    ],
    arms: {
      createAccountOp: xdr.lookup("CreateAccountOp"),
      paymentOp: xdr.lookup("PaymentOp"),
      pathPaymentStrictReceiveOp: xdr.lookup("PathPaymentStrictReceiveOp"),
      manageSellOfferOp: xdr.lookup("ManageSellOfferOp"),
      createPassiveSellOfferOp: xdr.lookup("CreatePassiveSellOfferOp"),
      setOptionsOp: xdr.lookup("SetOptionsOp"),
      changeTrustOp: xdr.lookup("ChangeTrustOp"),
      allowTrustOp: xdr.lookup("AllowTrustOp"),
      destination: xdr.lookup("MuxedAccount"),
      manageDataOp: xdr.lookup("ManageDataOp"),
      bumpSequenceOp: xdr.lookup("BumpSequenceOp"),
      manageBuyOfferOp: xdr.lookup("ManageBuyOfferOp"),
      pathPaymentStrictSendOp: xdr.lookup("PathPaymentStrictSendOp"),
      createClaimableBalanceOp: xdr.lookup("CreateClaimableBalanceOp"),
      claimClaimableBalanceOp: xdr.lookup("ClaimClaimableBalanceOp"),
      beginSponsoringFutureReservesOp: xdr.lookup(
        "BeginSponsoringFutureReservesOp"
      ),
      revokeSponsorshipOp: xdr.lookup("RevokeSponsorshipOp"),
      clawbackOp: xdr.lookup("ClawbackOp"),
      clawbackClaimableBalanceOp: xdr.lookup("ClawbackClaimableBalanceOp"),
      setTrustLineFlagsOp: xdr.lookup("SetTrustLineFlagsOp"),
      liquidityPoolDepositOp: xdr.lookup("LiquidityPoolDepositOp"),
      liquidityPoolWithdrawOp: xdr.lookup("LiquidityPoolWithdrawOp"),
      invokeHostFunctionOp: xdr.lookup("InvokeHostFunctionOp"),
      extendFootprintTtlOp: xdr.lookup("ExtendFootprintTtlOp"),
      restoreFootprintOp: xdr.lookup("RestoreFootprintOp")
    }
  });
  xdr.struct("Operation", [
    ["sourceAccount", xdr.option(xdr.lookup("MuxedAccount"))],
    ["body", xdr.lookup("OperationBody")]
  ]);
  xdr.struct("HashIdPreimageOperationId", [
    ["sourceAccount", xdr.lookup("AccountId")],
    ["seqNum", xdr.lookup("SequenceNumber")],
    ["opNum", xdr.lookup("Uint32")]
  ]);
  xdr.struct("HashIdPreimageRevokeId", [
    ["sourceAccount", xdr.lookup("AccountId")],
    ["seqNum", xdr.lookup("SequenceNumber")],
    ["opNum", xdr.lookup("Uint32")],
    ["liquidityPoolId", xdr.lookup("PoolId")],
    ["asset", xdr.lookup("Asset")]
  ]);
  xdr.struct("HashIdPreimageContractId", [
    ["networkId", xdr.lookup("Hash")],
    ["contractIdPreimage", xdr.lookup("ContractIdPreimage")]
  ]);
  xdr.struct("HashIdPreimageSorobanAuthorization", [
    ["networkId", xdr.lookup("Hash")],
    ["nonce", xdr.lookup("Int64")],
    ["signatureExpirationLedger", xdr.lookup("Uint32")],
    ["invocation", xdr.lookup("SorobanAuthorizedInvocation")]
  ]);
  xdr.struct("HashIdPreimageSorobanAuthorizationWithAddress", [
    ["networkId", xdr.lookup("Hash")],
    ["nonce", xdr.lookup("Int64")],
    ["signatureExpirationLedger", xdr.lookup("Uint32")],
    ["address", xdr.lookup("ScAddress")],
    ["invocation", xdr.lookup("SorobanAuthorizedInvocation")]
  ]);
  xdr.union("HashIdPreimage", {
    switchOn: xdr.lookup("EnvelopeType"),
    switchName: "type",
    switches: [
      ["envelopeTypeOpId", "operationId"],
      ["envelopeTypePoolRevokeOpId", "revokeId"],
      ["envelopeTypeContractId", "contractId"],
      ["envelopeTypeSorobanAuthorization", "sorobanAuthorization"],
      [
        "envelopeTypeSorobanAuthorizationWithAddress",
        "sorobanAuthorizationWithAddress"
      ]
    ],
    arms: {
      operationId: xdr.lookup("HashIdPreimageOperationId"),
      revokeId: xdr.lookup("HashIdPreimageRevokeId"),
      contractId: xdr.lookup("HashIdPreimageContractId"),
      sorobanAuthorization: xdr.lookup("HashIdPreimageSorobanAuthorization"),
      sorobanAuthorizationWithAddress: xdr.lookup(
        "HashIdPreimageSorobanAuthorizationWithAddress"
      )
    }
  });
  xdr.enum("MemoType", {
    memoNone: 0,
    memoText: 1,
    memoId: 2,
    memoHash: 3,
    memoReturn: 4
  });
  xdr.union("Memo", {
    switchOn: xdr.lookup("MemoType"),
    switchName: "type",
    switches: [
      ["memoNone", xdr.void()],
      ["memoText", "text"],
      ["memoId", "id"],
      ["memoHash", "hash"],
      ["memoReturn", "retHash"]
    ],
    arms: {
      text: xdr.string(28),
      id: xdr.lookup("Uint64"),
      hash: xdr.lookup("Hash"),
      retHash: xdr.lookup("Hash")
    }
  });
  xdr.struct("TimeBounds", [
    ["minTime", xdr.lookup("TimePoint")],
    ["maxTime", xdr.lookup("TimePoint")]
  ]);
  xdr.struct("LedgerBounds", [
    ["minLedger", xdr.lookup("Uint32")],
    ["maxLedger", xdr.lookup("Uint32")]
  ]);
  xdr.struct("PreconditionsV2", [
    ["timeBounds", xdr.option(xdr.lookup("TimeBounds"))],
    ["ledgerBounds", xdr.option(xdr.lookup("LedgerBounds"))],
    ["minSeqNum", xdr.option(xdr.lookup("SequenceNumber"))],
    ["minSeqAge", xdr.lookup("Duration")],
    ["minSeqLedgerGap", xdr.lookup("Uint32")],
    ["extraSigners", xdr.varArray(xdr.lookup("SignerKey"), 2)]
  ]);
  xdr.enum("PreconditionType", {
    precondNone: 0,
    precondTime: 1,
    precondV2: 2
  });
  xdr.union("Preconditions", {
    switchOn: xdr.lookup("PreconditionType"),
    switchName: "type",
    switches: [
      ["precondNone", xdr.void()],
      ["precondTime", "timeBounds"],
      ["precondV2", "v2"]
    ],
    arms: {
      timeBounds: xdr.lookup("TimeBounds"),
      v2: xdr.lookup("PreconditionsV2")
    }
  });
  xdr.struct("LedgerFootprint", [
    ["readOnly", xdr.varArray(xdr.lookup("LedgerKey"), 2147483647)],
    ["readWrite", xdr.varArray(xdr.lookup("LedgerKey"), 2147483647)]
  ]);
  xdr.struct("SorobanResources", [
    ["footprint", xdr.lookup("LedgerFootprint")],
    ["instructions", xdr.lookup("Uint32")],
    ["diskReadBytes", xdr.lookup("Uint32")],
    ["writeBytes", xdr.lookup("Uint32")]
  ]);
  xdr.struct("SorobanResourcesExtV0", [
    ["archivedSorobanEntries", xdr.varArray(xdr.lookup("Uint32"), 2147483647)]
  ]);
  xdr.union("SorobanTransactionDataExt", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [
      [0, xdr.void()],
      [1, "resourceExt"]
    ],
    arms: {
      resourceExt: xdr.lookup("SorobanResourcesExtV0")
    }
  });
  xdr.struct("SorobanTransactionData", [
    ["ext", xdr.lookup("SorobanTransactionDataExt")],
    ["resources", xdr.lookup("SorobanResources")],
    ["resourceFee", xdr.lookup("Int64")]
  ]);
  xdr.union("TransactionV0Ext", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [[0, xdr.void()]],
    arms: {}
  });
  xdr.struct("TransactionV0", [
    ["sourceAccountEd25519", xdr.lookup("Uint256")],
    ["fee", xdr.lookup("Uint32")],
    ["seqNum", xdr.lookup("SequenceNumber")],
    ["timeBounds", xdr.option(xdr.lookup("TimeBounds"))],
    ["memo", xdr.lookup("Memo")],
    [
      "operations",
      xdr.varArray(xdr.lookup("Operation"), xdr.lookup("MAX_OPS_PER_TX"))
    ],
    ["ext", xdr.lookup("TransactionV0Ext")]
  ]);
  xdr.struct("TransactionV0Envelope", [
    ["tx", xdr.lookup("TransactionV0")],
    ["signatures", xdr.varArray(xdr.lookup("DecoratedSignature"), 20)]
  ]);
  xdr.union("TransactionExt", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [
      [0, xdr.void()],
      [1, "sorobanData"]
    ],
    arms: {
      sorobanData: xdr.lookup("SorobanTransactionData")
    }
  });
  xdr.struct("Transaction", [
    ["sourceAccount", xdr.lookup("MuxedAccount")],
    ["fee", xdr.lookup("Uint32")],
    ["seqNum", xdr.lookup("SequenceNumber")],
    ["cond", xdr.lookup("Preconditions")],
    ["memo", xdr.lookup("Memo")],
    [
      "operations",
      xdr.varArray(xdr.lookup("Operation"), xdr.lookup("MAX_OPS_PER_TX"))
    ],
    ["ext", xdr.lookup("TransactionExt")]
  ]);
  xdr.struct("TransactionV1Envelope", [
    ["tx", xdr.lookup("Transaction")],
    ["signatures", xdr.varArray(xdr.lookup("DecoratedSignature"), 20)]
  ]);
  xdr.union("FeeBumpTransactionInnerTx", {
    switchOn: xdr.lookup("EnvelopeType"),
    switchName: "type",
    switches: [["envelopeTypeTx", "v1"]],
    arms: {
      v1: xdr.lookup("TransactionV1Envelope")
    }
  });
  xdr.union("FeeBumpTransactionExt", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [[0, xdr.void()]],
    arms: {}
  });
  xdr.struct("FeeBumpTransaction", [
    ["feeSource", xdr.lookup("MuxedAccount")],
    ["fee", xdr.lookup("Int64")],
    ["innerTx", xdr.lookup("FeeBumpTransactionInnerTx")],
    ["ext", xdr.lookup("FeeBumpTransactionExt")]
  ]);
  xdr.struct("FeeBumpTransactionEnvelope", [
    ["tx", xdr.lookup("FeeBumpTransaction")],
    ["signatures", xdr.varArray(xdr.lookup("DecoratedSignature"), 20)]
  ]);
  xdr.union("TransactionEnvelope", {
    switchOn: xdr.lookup("EnvelopeType"),
    switchName: "type",
    switches: [
      ["envelopeTypeTxV0", "v0"],
      ["envelopeTypeTx", "v1"],
      ["envelopeTypeTxFeeBump", "feeBump"]
    ],
    arms: {
      v0: xdr.lookup("TransactionV0Envelope"),
      v1: xdr.lookup("TransactionV1Envelope"),
      feeBump: xdr.lookup("FeeBumpTransactionEnvelope")
    }
  });
  xdr.union("TransactionSignaturePayloadTaggedTransaction", {
    switchOn: xdr.lookup("EnvelopeType"),
    switchName: "type",
    switches: [
      ["envelopeTypeTx", "tx"],
      ["envelopeTypeTxFeeBump", "feeBump"]
    ],
    arms: {
      tx: xdr.lookup("Transaction"),
      feeBump: xdr.lookup("FeeBumpTransaction")
    }
  });
  xdr.struct("TransactionSignaturePayload", [
    ["networkId", xdr.lookup("Hash")],
    [
      "taggedTransaction",
      xdr.lookup("TransactionSignaturePayloadTaggedTransaction")
    ]
  ]);
  xdr.enum("ClaimAtomType", {
    claimAtomTypeV0: 0,
    claimAtomTypeOrderBook: 1,
    claimAtomTypeLiquidityPool: 2
  });
  xdr.struct("ClaimOfferAtomV0", [
    ["sellerEd25519", xdr.lookup("Uint256")],
    ["offerId", xdr.lookup("Int64")],
    ["assetSold", xdr.lookup("Asset")],
    ["amountSold", xdr.lookup("Int64")],
    ["assetBought", xdr.lookup("Asset")],
    ["amountBought", xdr.lookup("Int64")]
  ]);
  xdr.struct("ClaimOfferAtom", [
    ["sellerId", xdr.lookup("AccountId")],
    ["offerId", xdr.lookup("Int64")],
    ["assetSold", xdr.lookup("Asset")],
    ["amountSold", xdr.lookup("Int64")],
    ["assetBought", xdr.lookup("Asset")],
    ["amountBought", xdr.lookup("Int64")]
  ]);
  xdr.struct("ClaimLiquidityAtom", [
    ["liquidityPoolId", xdr.lookup("PoolId")],
    ["assetSold", xdr.lookup("Asset")],
    ["amountSold", xdr.lookup("Int64")],
    ["assetBought", xdr.lookup("Asset")],
    ["amountBought", xdr.lookup("Int64")]
  ]);
  xdr.union("ClaimAtom", {
    switchOn: xdr.lookup("ClaimAtomType"),
    switchName: "type",
    switches: [
      ["claimAtomTypeV0", "v0"],
      ["claimAtomTypeOrderBook", "orderBook"],
      ["claimAtomTypeLiquidityPool", "liquidityPool"]
    ],
    arms: {
      v0: xdr.lookup("ClaimOfferAtomV0"),
      orderBook: xdr.lookup("ClaimOfferAtom"),
      liquidityPool: xdr.lookup("ClaimLiquidityAtom")
    }
  });
  xdr.enum("CreateAccountResultCode", {
    createAccountSuccess: 0,
    createAccountMalformed: -1,
    createAccountUnderfunded: -2,
    createAccountLowReserve: -3,
    createAccountAlreadyExist: -4
  });
  xdr.union("CreateAccountResult", {
    switchOn: xdr.lookup("CreateAccountResultCode"),
    switchName: "code",
    switches: [
      ["createAccountSuccess", xdr.void()],
      ["createAccountMalformed", xdr.void()],
      ["createAccountUnderfunded", xdr.void()],
      ["createAccountLowReserve", xdr.void()],
      ["createAccountAlreadyExist", xdr.void()]
    ],
    arms: {}
  });
  xdr.enum("PaymentResultCode", {
    paymentSuccess: 0,
    paymentMalformed: -1,
    paymentUnderfunded: -2,
    paymentSrcNoTrust: -3,
    paymentSrcNotAuthorized: -4,
    paymentNoDestination: -5,
    paymentNoTrust: -6,
    paymentNotAuthorized: -7,
    paymentLineFull: -8,
    paymentNoIssuer: -9
  });
  xdr.union("PaymentResult", {
    switchOn: xdr.lookup("PaymentResultCode"),
    switchName: "code",
    switches: [
      ["paymentSuccess", xdr.void()],
      ["paymentMalformed", xdr.void()],
      ["paymentUnderfunded", xdr.void()],
      ["paymentSrcNoTrust", xdr.void()],
      ["paymentSrcNotAuthorized", xdr.void()],
      ["paymentNoDestination", xdr.void()],
      ["paymentNoTrust", xdr.void()],
      ["paymentNotAuthorized", xdr.void()],
      ["paymentLineFull", xdr.void()],
      ["paymentNoIssuer", xdr.void()]
    ],
    arms: {}
  });
  xdr.enum("PathPaymentStrictReceiveResultCode", {
    pathPaymentStrictReceiveSuccess: 0,
    pathPaymentStrictReceiveMalformed: -1,
    pathPaymentStrictReceiveUnderfunded: -2,
    pathPaymentStrictReceiveSrcNoTrust: -3,
    pathPaymentStrictReceiveSrcNotAuthorized: -4,
    pathPaymentStrictReceiveNoDestination: -5,
    pathPaymentStrictReceiveNoTrust: -6,
    pathPaymentStrictReceiveNotAuthorized: -7,
    pathPaymentStrictReceiveLineFull: -8,
    pathPaymentStrictReceiveNoIssuer: -9,
    pathPaymentStrictReceiveTooFewOffers: -10,
    pathPaymentStrictReceiveOfferCrossSelf: -11,
    pathPaymentStrictReceiveOverSendmax: -12
  });
  xdr.struct("SimplePaymentResult", [
    ["destination", xdr.lookup("AccountId")],
    ["asset", xdr.lookup("Asset")],
    ["amount", xdr.lookup("Int64")]
  ]);
  xdr.struct("PathPaymentStrictReceiveResultSuccess", [
    ["offers", xdr.varArray(xdr.lookup("ClaimAtom"), 2147483647)],
    ["last", xdr.lookup("SimplePaymentResult")]
  ]);
  xdr.union("PathPaymentStrictReceiveResult", {
    switchOn: xdr.lookup("PathPaymentStrictReceiveResultCode"),
    switchName: "code",
    switches: [
      ["pathPaymentStrictReceiveSuccess", "success"],
      ["pathPaymentStrictReceiveMalformed", xdr.void()],
      ["pathPaymentStrictReceiveUnderfunded", xdr.void()],
      ["pathPaymentStrictReceiveSrcNoTrust", xdr.void()],
      ["pathPaymentStrictReceiveSrcNotAuthorized", xdr.void()],
      ["pathPaymentStrictReceiveNoDestination", xdr.void()],
      ["pathPaymentStrictReceiveNoTrust", xdr.void()],
      ["pathPaymentStrictReceiveNotAuthorized", xdr.void()],
      ["pathPaymentStrictReceiveLineFull", xdr.void()],
      ["pathPaymentStrictReceiveNoIssuer", "noIssuer"],
      ["pathPaymentStrictReceiveTooFewOffers", xdr.void()],
      ["pathPaymentStrictReceiveOfferCrossSelf", xdr.void()],
      ["pathPaymentStrictReceiveOverSendmax", xdr.void()]
    ],
    arms: {
      success: xdr.lookup("PathPaymentStrictReceiveResultSuccess"),
      noIssuer: xdr.lookup("Asset")
    }
  });
  xdr.enum("PathPaymentStrictSendResultCode", {
    pathPaymentStrictSendSuccess: 0,
    pathPaymentStrictSendMalformed: -1,
    pathPaymentStrictSendUnderfunded: -2,
    pathPaymentStrictSendSrcNoTrust: -3,
    pathPaymentStrictSendSrcNotAuthorized: -4,
    pathPaymentStrictSendNoDestination: -5,
    pathPaymentStrictSendNoTrust: -6,
    pathPaymentStrictSendNotAuthorized: -7,
    pathPaymentStrictSendLineFull: -8,
    pathPaymentStrictSendNoIssuer: -9,
    pathPaymentStrictSendTooFewOffers: -10,
    pathPaymentStrictSendOfferCrossSelf: -11,
    pathPaymentStrictSendUnderDestmin: -12
  });
  xdr.struct("PathPaymentStrictSendResultSuccess", [
    ["offers", xdr.varArray(xdr.lookup("ClaimAtom"), 2147483647)],
    ["last", xdr.lookup("SimplePaymentResult")]
  ]);
  xdr.union("PathPaymentStrictSendResult", {
    switchOn: xdr.lookup("PathPaymentStrictSendResultCode"),
    switchName: "code",
    switches: [
      ["pathPaymentStrictSendSuccess", "success"],
      ["pathPaymentStrictSendMalformed", xdr.void()],
      ["pathPaymentStrictSendUnderfunded", xdr.void()],
      ["pathPaymentStrictSendSrcNoTrust", xdr.void()],
      ["pathPaymentStrictSendSrcNotAuthorized", xdr.void()],
      ["pathPaymentStrictSendNoDestination", xdr.void()],
      ["pathPaymentStrictSendNoTrust", xdr.void()],
      ["pathPaymentStrictSendNotAuthorized", xdr.void()],
      ["pathPaymentStrictSendLineFull", xdr.void()],
      ["pathPaymentStrictSendNoIssuer", "noIssuer"],
      ["pathPaymentStrictSendTooFewOffers", xdr.void()],
      ["pathPaymentStrictSendOfferCrossSelf", xdr.void()],
      ["pathPaymentStrictSendUnderDestmin", xdr.void()]
    ],
    arms: {
      success: xdr.lookup("PathPaymentStrictSendResultSuccess"),
      noIssuer: xdr.lookup("Asset")
    }
  });
  xdr.enum("ManageSellOfferResultCode", {
    manageSellOfferSuccess: 0,
    manageSellOfferMalformed: -1,
    manageSellOfferSellNoTrust: -2,
    manageSellOfferBuyNoTrust: -3,
    manageSellOfferSellNotAuthorized: -4,
    manageSellOfferBuyNotAuthorized: -5,
    manageSellOfferLineFull: -6,
    manageSellOfferUnderfunded: -7,
    manageSellOfferCrossSelf: -8,
    manageSellOfferSellNoIssuer: -9,
    manageSellOfferBuyNoIssuer: -10,
    manageSellOfferNotFound: -11,
    manageSellOfferLowReserve: -12
  });
  xdr.enum("ManageOfferEffect", {
    manageOfferCreated: 0,
    manageOfferUpdated: 1,
    manageOfferDeleted: 2
  });
  xdr.union("ManageOfferSuccessResultOffer", {
    switchOn: xdr.lookup("ManageOfferEffect"),
    switchName: "effect",
    switches: [
      ["manageOfferCreated", "offer"],
      ["manageOfferUpdated", "offer"],
      ["manageOfferDeleted", xdr.void()]
    ],
    arms: {
      offer: xdr.lookup("OfferEntry")
    }
  });
  xdr.struct("ManageOfferSuccessResult", [
    ["offersClaimed", xdr.varArray(xdr.lookup("ClaimAtom"), 2147483647)],
    ["offer", xdr.lookup("ManageOfferSuccessResultOffer")]
  ]);
  xdr.union("ManageSellOfferResult", {
    switchOn: xdr.lookup("ManageSellOfferResultCode"),
    switchName: "code",
    switches: [
      ["manageSellOfferSuccess", "success"],
      ["manageSellOfferMalformed", xdr.void()],
      ["manageSellOfferSellNoTrust", xdr.void()],
      ["manageSellOfferBuyNoTrust", xdr.void()],
      ["manageSellOfferSellNotAuthorized", xdr.void()],
      ["manageSellOfferBuyNotAuthorized", xdr.void()],
      ["manageSellOfferLineFull", xdr.void()],
      ["manageSellOfferUnderfunded", xdr.void()],
      ["manageSellOfferCrossSelf", xdr.void()],
      ["manageSellOfferSellNoIssuer", xdr.void()],
      ["manageSellOfferBuyNoIssuer", xdr.void()],
      ["manageSellOfferNotFound", xdr.void()],
      ["manageSellOfferLowReserve", xdr.void()]
    ],
    arms: {
      success: xdr.lookup("ManageOfferSuccessResult")
    }
  });
  xdr.enum("ManageBuyOfferResultCode", {
    manageBuyOfferSuccess: 0,
    manageBuyOfferMalformed: -1,
    manageBuyOfferSellNoTrust: -2,
    manageBuyOfferBuyNoTrust: -3,
    manageBuyOfferSellNotAuthorized: -4,
    manageBuyOfferBuyNotAuthorized: -5,
    manageBuyOfferLineFull: -6,
    manageBuyOfferUnderfunded: -7,
    manageBuyOfferCrossSelf: -8,
    manageBuyOfferSellNoIssuer: -9,
    manageBuyOfferBuyNoIssuer: -10,
    manageBuyOfferNotFound: -11,
    manageBuyOfferLowReserve: -12
  });
  xdr.union("ManageBuyOfferResult", {
    switchOn: xdr.lookup("ManageBuyOfferResultCode"),
    switchName: "code",
    switches: [
      ["manageBuyOfferSuccess", "success"],
      ["manageBuyOfferMalformed", xdr.void()],
      ["manageBuyOfferSellNoTrust", xdr.void()],
      ["manageBuyOfferBuyNoTrust", xdr.void()],
      ["manageBuyOfferSellNotAuthorized", xdr.void()],
      ["manageBuyOfferBuyNotAuthorized", xdr.void()],
      ["manageBuyOfferLineFull", xdr.void()],
      ["manageBuyOfferUnderfunded", xdr.void()],
      ["manageBuyOfferCrossSelf", xdr.void()],
      ["manageBuyOfferSellNoIssuer", xdr.void()],
      ["manageBuyOfferBuyNoIssuer", xdr.void()],
      ["manageBuyOfferNotFound", xdr.void()],
      ["manageBuyOfferLowReserve", xdr.void()]
    ],
    arms: {
      success: xdr.lookup("ManageOfferSuccessResult")
    }
  });
  xdr.enum("SetOptionsResultCode", {
    setOptionsSuccess: 0,
    setOptionsLowReserve: -1,
    setOptionsTooManySigners: -2,
    setOptionsBadFlags: -3,
    setOptionsInvalidInflation: -4,
    setOptionsCantChange: -5,
    setOptionsUnknownFlag: -6,
    setOptionsThresholdOutOfRange: -7,
    setOptionsBadSigner: -8,
    setOptionsInvalidHomeDomain: -9,
    setOptionsAuthRevocableRequired: -10
  });
  xdr.union("SetOptionsResult", {
    switchOn: xdr.lookup("SetOptionsResultCode"),
    switchName: "code",
    switches: [
      ["setOptionsSuccess", xdr.void()],
      ["setOptionsLowReserve", xdr.void()],
      ["setOptionsTooManySigners", xdr.void()],
      ["setOptionsBadFlags", xdr.void()],
      ["setOptionsInvalidInflation", xdr.void()],
      ["setOptionsCantChange", xdr.void()],
      ["setOptionsUnknownFlag", xdr.void()],
      ["setOptionsThresholdOutOfRange", xdr.void()],
      ["setOptionsBadSigner", xdr.void()],
      ["setOptionsInvalidHomeDomain", xdr.void()],
      ["setOptionsAuthRevocableRequired", xdr.void()]
    ],
    arms: {}
  });
  xdr.enum("ChangeTrustResultCode", {
    changeTrustSuccess: 0,
    changeTrustMalformed: -1,
    changeTrustNoIssuer: -2,
    changeTrustInvalidLimit: -3,
    changeTrustLowReserve: -4,
    changeTrustSelfNotAllowed: -5,
    changeTrustTrustLineMissing: -6,
    changeTrustCannotDelete: -7,
    changeTrustNotAuthMaintainLiabilities: -8
  });
  xdr.union("ChangeTrustResult", {
    switchOn: xdr.lookup("ChangeTrustResultCode"),
    switchName: "code",
    switches: [
      ["changeTrustSuccess", xdr.void()],
      ["changeTrustMalformed", xdr.void()],
      ["changeTrustNoIssuer", xdr.void()],
      ["changeTrustInvalidLimit", xdr.void()],
      ["changeTrustLowReserve", xdr.void()],
      ["changeTrustSelfNotAllowed", xdr.void()],
      ["changeTrustTrustLineMissing", xdr.void()],
      ["changeTrustCannotDelete", xdr.void()],
      ["changeTrustNotAuthMaintainLiabilities", xdr.void()]
    ],
    arms: {}
  });
  xdr.enum("AllowTrustResultCode", {
    allowTrustSuccess: 0,
    allowTrustMalformed: -1,
    allowTrustNoTrustLine: -2,
    allowTrustTrustNotRequired: -3,
    allowTrustCantRevoke: -4,
    allowTrustSelfNotAllowed: -5,
    allowTrustLowReserve: -6
  });
  xdr.union("AllowTrustResult", {
    switchOn: xdr.lookup("AllowTrustResultCode"),
    switchName: "code",
    switches: [
      ["allowTrustSuccess", xdr.void()],
      ["allowTrustMalformed", xdr.void()],
      ["allowTrustNoTrustLine", xdr.void()],
      ["allowTrustTrustNotRequired", xdr.void()],
      ["allowTrustCantRevoke", xdr.void()],
      ["allowTrustSelfNotAllowed", xdr.void()],
      ["allowTrustLowReserve", xdr.void()]
    ],
    arms: {}
  });
  xdr.enum("AccountMergeResultCode", {
    accountMergeSuccess: 0,
    accountMergeMalformed: -1,
    accountMergeNoAccount: -2,
    accountMergeImmutableSet: -3,
    accountMergeHasSubEntries: -4,
    accountMergeSeqnumTooFar: -5,
    accountMergeDestFull: -6,
    accountMergeIsSponsor: -7
  });
  xdr.union("AccountMergeResult", {
    switchOn: xdr.lookup("AccountMergeResultCode"),
    switchName: "code",
    switches: [
      ["accountMergeSuccess", "sourceAccountBalance"],
      ["accountMergeMalformed", xdr.void()],
      ["accountMergeNoAccount", xdr.void()],
      ["accountMergeImmutableSet", xdr.void()],
      ["accountMergeHasSubEntries", xdr.void()],
      ["accountMergeSeqnumTooFar", xdr.void()],
      ["accountMergeDestFull", xdr.void()],
      ["accountMergeIsSponsor", xdr.void()]
    ],
    arms: {
      sourceAccountBalance: xdr.lookup("Int64")
    }
  });
  xdr.enum("InflationResultCode", {
    inflationSuccess: 0,
    inflationNotTime: -1
  });
  xdr.struct("InflationPayout", [
    ["destination", xdr.lookup("AccountId")],
    ["amount", xdr.lookup("Int64")]
  ]);
  xdr.union("InflationResult", {
    switchOn: xdr.lookup("InflationResultCode"),
    switchName: "code",
    switches: [
      ["inflationSuccess", "payouts"],
      ["inflationNotTime", xdr.void()]
    ],
    arms: {
      payouts: xdr.varArray(xdr.lookup("InflationPayout"), 2147483647)
    }
  });
  xdr.enum("ManageDataResultCode", {
    manageDataSuccess: 0,
    manageDataNotSupportedYet: -1,
    manageDataNameNotFound: -2,
    manageDataLowReserve: -3,
    manageDataInvalidName: -4
  });
  xdr.union("ManageDataResult", {
    switchOn: xdr.lookup("ManageDataResultCode"),
    switchName: "code",
    switches: [
      ["manageDataSuccess", xdr.void()],
      ["manageDataNotSupportedYet", xdr.void()],
      ["manageDataNameNotFound", xdr.void()],
      ["manageDataLowReserve", xdr.void()],
      ["manageDataInvalidName", xdr.void()]
    ],
    arms: {}
  });
  xdr.enum("BumpSequenceResultCode", {
    bumpSequenceSuccess: 0,
    bumpSequenceBadSeq: -1
  });
  xdr.union("BumpSequenceResult", {
    switchOn: xdr.lookup("BumpSequenceResultCode"),
    switchName: "code",
    switches: [
      ["bumpSequenceSuccess", xdr.void()],
      ["bumpSequenceBadSeq", xdr.void()]
    ],
    arms: {}
  });
  xdr.enum("CreateClaimableBalanceResultCode", {
    createClaimableBalanceSuccess: 0,
    createClaimableBalanceMalformed: -1,
    createClaimableBalanceLowReserve: -2,
    createClaimableBalanceNoTrust: -3,
    createClaimableBalanceNotAuthorized: -4,
    createClaimableBalanceUnderfunded: -5
  });
  xdr.union("CreateClaimableBalanceResult", {
    switchOn: xdr.lookup("CreateClaimableBalanceResultCode"),
    switchName: "code",
    switches: [
      ["createClaimableBalanceSuccess", "balanceId"],
      ["createClaimableBalanceMalformed", xdr.void()],
      ["createClaimableBalanceLowReserve", xdr.void()],
      ["createClaimableBalanceNoTrust", xdr.void()],
      ["createClaimableBalanceNotAuthorized", xdr.void()],
      ["createClaimableBalanceUnderfunded", xdr.void()]
    ],
    arms: {
      balanceId: xdr.lookup("ClaimableBalanceId")
    }
  });
  xdr.enum("ClaimClaimableBalanceResultCode", {
    claimClaimableBalanceSuccess: 0,
    claimClaimableBalanceDoesNotExist: -1,
    claimClaimableBalanceCannotClaim: -2,
    claimClaimableBalanceLineFull: -3,
    claimClaimableBalanceNoTrust: -4,
    claimClaimableBalanceNotAuthorized: -5,
    claimClaimableBalanceTrustlineFrozen: -6
  });
  xdr.union("ClaimClaimableBalanceResult", {
    switchOn: xdr.lookup("ClaimClaimableBalanceResultCode"),
    switchName: "code",
    switches: [
      ["claimClaimableBalanceSuccess", xdr.void()],
      ["claimClaimableBalanceDoesNotExist", xdr.void()],
      ["claimClaimableBalanceCannotClaim", xdr.void()],
      ["claimClaimableBalanceLineFull", xdr.void()],
      ["claimClaimableBalanceNoTrust", xdr.void()],
      ["claimClaimableBalanceNotAuthorized", xdr.void()],
      ["claimClaimableBalanceTrustlineFrozen", xdr.void()]
    ],
    arms: {}
  });
  xdr.enum("BeginSponsoringFutureReservesResultCode", {
    beginSponsoringFutureReservesSuccess: 0,
    beginSponsoringFutureReservesMalformed: -1,
    beginSponsoringFutureReservesAlreadySponsored: -2,
    beginSponsoringFutureReservesRecursive: -3
  });
  xdr.union("BeginSponsoringFutureReservesResult", {
    switchOn: xdr.lookup("BeginSponsoringFutureReservesResultCode"),
    switchName: "code",
    switches: [
      ["beginSponsoringFutureReservesSuccess", xdr.void()],
      ["beginSponsoringFutureReservesMalformed", xdr.void()],
      ["beginSponsoringFutureReservesAlreadySponsored", xdr.void()],
      ["beginSponsoringFutureReservesRecursive", xdr.void()]
    ],
    arms: {}
  });
  xdr.enum("EndSponsoringFutureReservesResultCode", {
    endSponsoringFutureReservesSuccess: 0,
    endSponsoringFutureReservesNotSponsored: -1
  });
  xdr.union("EndSponsoringFutureReservesResult", {
    switchOn: xdr.lookup("EndSponsoringFutureReservesResultCode"),
    switchName: "code",
    switches: [
      ["endSponsoringFutureReservesSuccess", xdr.void()],
      ["endSponsoringFutureReservesNotSponsored", xdr.void()]
    ],
    arms: {}
  });
  xdr.enum("RevokeSponsorshipResultCode", {
    revokeSponsorshipSuccess: 0,
    revokeSponsorshipDoesNotExist: -1,
    revokeSponsorshipNotSponsor: -2,
    revokeSponsorshipLowReserve: -3,
    revokeSponsorshipOnlyTransferable: -4,
    revokeSponsorshipMalformed: -5
  });
  xdr.union("RevokeSponsorshipResult", {
    switchOn: xdr.lookup("RevokeSponsorshipResultCode"),
    switchName: "code",
    switches: [
      ["revokeSponsorshipSuccess", xdr.void()],
      ["revokeSponsorshipDoesNotExist", xdr.void()],
      ["revokeSponsorshipNotSponsor", xdr.void()],
      ["revokeSponsorshipLowReserve", xdr.void()],
      ["revokeSponsorshipOnlyTransferable", xdr.void()],
      ["revokeSponsorshipMalformed", xdr.void()]
    ],
    arms: {}
  });
  xdr.enum("ClawbackResultCode", {
    clawbackSuccess: 0,
    clawbackMalformed: -1,
    clawbackNotClawbackEnabled: -2,
    clawbackNoTrust: -3,
    clawbackUnderfunded: -4
  });
  xdr.union("ClawbackResult", {
    switchOn: xdr.lookup("ClawbackResultCode"),
    switchName: "code",
    switches: [
      ["clawbackSuccess", xdr.void()],
      ["clawbackMalformed", xdr.void()],
      ["clawbackNotClawbackEnabled", xdr.void()],
      ["clawbackNoTrust", xdr.void()],
      ["clawbackUnderfunded", xdr.void()]
    ],
    arms: {}
  });
  xdr.enum("ClawbackClaimableBalanceResultCode", {
    clawbackClaimableBalanceSuccess: 0,
    clawbackClaimableBalanceDoesNotExist: -1,
    clawbackClaimableBalanceNotIssuer: -2,
    clawbackClaimableBalanceNotClawbackEnabled: -3
  });
  xdr.union("ClawbackClaimableBalanceResult", {
    switchOn: xdr.lookup("ClawbackClaimableBalanceResultCode"),
    switchName: "code",
    switches: [
      ["clawbackClaimableBalanceSuccess", xdr.void()],
      ["clawbackClaimableBalanceDoesNotExist", xdr.void()],
      ["clawbackClaimableBalanceNotIssuer", xdr.void()],
      ["clawbackClaimableBalanceNotClawbackEnabled", xdr.void()]
    ],
    arms: {}
  });
  xdr.enum("SetTrustLineFlagsResultCode", {
    setTrustLineFlagsSuccess: 0,
    setTrustLineFlagsMalformed: -1,
    setTrustLineFlagsNoTrustLine: -2,
    setTrustLineFlagsCantRevoke: -3,
    setTrustLineFlagsInvalidState: -4,
    setTrustLineFlagsLowReserve: -5
  });
  xdr.union("SetTrustLineFlagsResult", {
    switchOn: xdr.lookup("SetTrustLineFlagsResultCode"),
    switchName: "code",
    switches: [
      ["setTrustLineFlagsSuccess", xdr.void()],
      ["setTrustLineFlagsMalformed", xdr.void()],
      ["setTrustLineFlagsNoTrustLine", xdr.void()],
      ["setTrustLineFlagsCantRevoke", xdr.void()],
      ["setTrustLineFlagsInvalidState", xdr.void()],
      ["setTrustLineFlagsLowReserve", xdr.void()]
    ],
    arms: {}
  });
  xdr.enum("LiquidityPoolDepositResultCode", {
    liquidityPoolDepositSuccess: 0,
    liquidityPoolDepositMalformed: -1,
    liquidityPoolDepositNoTrust: -2,
    liquidityPoolDepositNotAuthorized: -3,
    liquidityPoolDepositUnderfunded: -4,
    liquidityPoolDepositLineFull: -5,
    liquidityPoolDepositBadPrice: -6,
    liquidityPoolDepositPoolFull: -7,
    liquidityPoolDepositTrustlineFrozen: -8
  });
  xdr.union("LiquidityPoolDepositResult", {
    switchOn: xdr.lookup("LiquidityPoolDepositResultCode"),
    switchName: "code",
    switches: [
      ["liquidityPoolDepositSuccess", xdr.void()],
      ["liquidityPoolDepositMalformed", xdr.void()],
      ["liquidityPoolDepositNoTrust", xdr.void()],
      ["liquidityPoolDepositNotAuthorized", xdr.void()],
      ["liquidityPoolDepositUnderfunded", xdr.void()],
      ["liquidityPoolDepositLineFull", xdr.void()],
      ["liquidityPoolDepositBadPrice", xdr.void()],
      ["liquidityPoolDepositPoolFull", xdr.void()],
      ["liquidityPoolDepositTrustlineFrozen", xdr.void()]
    ],
    arms: {}
  });
  xdr.enum("LiquidityPoolWithdrawResultCode", {
    liquidityPoolWithdrawSuccess: 0,
    liquidityPoolWithdrawMalformed: -1,
    liquidityPoolWithdrawNoTrust: -2,
    liquidityPoolWithdrawUnderfunded: -3,
    liquidityPoolWithdrawLineFull: -4,
    liquidityPoolWithdrawUnderMinimum: -5,
    liquidityPoolWithdrawTrustlineFrozen: -6
  });
  xdr.union("LiquidityPoolWithdrawResult", {
    switchOn: xdr.lookup("LiquidityPoolWithdrawResultCode"),
    switchName: "code",
    switches: [
      ["liquidityPoolWithdrawSuccess", xdr.void()],
      ["liquidityPoolWithdrawMalformed", xdr.void()],
      ["liquidityPoolWithdrawNoTrust", xdr.void()],
      ["liquidityPoolWithdrawUnderfunded", xdr.void()],
      ["liquidityPoolWithdrawLineFull", xdr.void()],
      ["liquidityPoolWithdrawUnderMinimum", xdr.void()],
      ["liquidityPoolWithdrawTrustlineFrozen", xdr.void()]
    ],
    arms: {}
  });
  xdr.enum("InvokeHostFunctionResultCode", {
    invokeHostFunctionSuccess: 0,
    invokeHostFunctionMalformed: -1,
    invokeHostFunctionTrapped: -2,
    invokeHostFunctionResourceLimitExceeded: -3,
    invokeHostFunctionEntryArchived: -4,
    invokeHostFunctionInsufficientRefundableFee: -5
  });
  xdr.union("InvokeHostFunctionResult", {
    switchOn: xdr.lookup("InvokeHostFunctionResultCode"),
    switchName: "code",
    switches: [
      ["invokeHostFunctionSuccess", "success"],
      ["invokeHostFunctionMalformed", xdr.void()],
      ["invokeHostFunctionTrapped", xdr.void()],
      ["invokeHostFunctionResourceLimitExceeded", xdr.void()],
      ["invokeHostFunctionEntryArchived", xdr.void()],
      ["invokeHostFunctionInsufficientRefundableFee", xdr.void()]
    ],
    arms: {
      success: xdr.lookup("Hash")
    }
  });
  xdr.enum("ExtendFootprintTtlResultCode", {
    extendFootprintTtlSuccess: 0,
    extendFootprintTtlMalformed: -1,
    extendFootprintTtlResourceLimitExceeded: -2,
    extendFootprintTtlInsufficientRefundableFee: -3
  });
  xdr.union("ExtendFootprintTtlResult", {
    switchOn: xdr.lookup("ExtendFootprintTtlResultCode"),
    switchName: "code",
    switches: [
      ["extendFootprintTtlSuccess", xdr.void()],
      ["extendFootprintTtlMalformed", xdr.void()],
      ["extendFootprintTtlResourceLimitExceeded", xdr.void()],
      ["extendFootprintTtlInsufficientRefundableFee", xdr.void()]
    ],
    arms: {}
  });
  xdr.enum("RestoreFootprintResultCode", {
    restoreFootprintSuccess: 0,
    restoreFootprintMalformed: -1,
    restoreFootprintResourceLimitExceeded: -2,
    restoreFootprintInsufficientRefundableFee: -3
  });
  xdr.union("RestoreFootprintResult", {
    switchOn: xdr.lookup("RestoreFootprintResultCode"),
    switchName: "code",
    switches: [
      ["restoreFootprintSuccess", xdr.void()],
      ["restoreFootprintMalformed", xdr.void()],
      ["restoreFootprintResourceLimitExceeded", xdr.void()],
      ["restoreFootprintInsufficientRefundableFee", xdr.void()]
    ],
    arms: {}
  });
  xdr.enum("OperationResultCode", {
    opInner: 0,
    opBadAuth: -1,
    opNoAccount: -2,
    opNotSupported: -3,
    opTooManySubentries: -4,
    opExceededWorkLimit: -5,
    opTooManySponsoring: -6
  });
  xdr.union("OperationResultTr", {
    switchOn: xdr.lookup("OperationType"),
    switchName: "type",
    switches: [
      ["createAccount", "createAccountResult"],
      ["payment", "paymentResult"],
      ["pathPaymentStrictReceive", "pathPaymentStrictReceiveResult"],
      ["manageSellOffer", "manageSellOfferResult"],
      ["createPassiveSellOffer", "createPassiveSellOfferResult"],
      ["setOptions", "setOptionsResult"],
      ["changeTrust", "changeTrustResult"],
      ["allowTrust", "allowTrustResult"],
      ["accountMerge", "accountMergeResult"],
      ["inflation", "inflationResult"],
      ["manageData", "manageDataResult"],
      ["bumpSequence", "bumpSeqResult"],
      ["manageBuyOffer", "manageBuyOfferResult"],
      ["pathPaymentStrictSend", "pathPaymentStrictSendResult"],
      ["createClaimableBalance", "createClaimableBalanceResult"],
      ["claimClaimableBalance", "claimClaimableBalanceResult"],
      ["beginSponsoringFutureReserves", "beginSponsoringFutureReservesResult"],
      ["endSponsoringFutureReserves", "endSponsoringFutureReservesResult"],
      ["revokeSponsorship", "revokeSponsorshipResult"],
      ["clawback", "clawbackResult"],
      ["clawbackClaimableBalance", "clawbackClaimableBalanceResult"],
      ["setTrustLineFlags", "setTrustLineFlagsResult"],
      ["liquidityPoolDeposit", "liquidityPoolDepositResult"],
      ["liquidityPoolWithdraw", "liquidityPoolWithdrawResult"],
      ["invokeHostFunction", "invokeHostFunctionResult"],
      ["extendFootprintTtl", "extendFootprintTtlResult"],
      ["restoreFootprint", "restoreFootprintResult"]
    ],
    arms: {
      createAccountResult: xdr.lookup("CreateAccountResult"),
      paymentResult: xdr.lookup("PaymentResult"),
      pathPaymentStrictReceiveResult: xdr.lookup(
        "PathPaymentStrictReceiveResult"
      ),
      manageSellOfferResult: xdr.lookup("ManageSellOfferResult"),
      createPassiveSellOfferResult: xdr.lookup("ManageSellOfferResult"),
      setOptionsResult: xdr.lookup("SetOptionsResult"),
      changeTrustResult: xdr.lookup("ChangeTrustResult"),
      allowTrustResult: xdr.lookup("AllowTrustResult"),
      accountMergeResult: xdr.lookup("AccountMergeResult"),
      inflationResult: xdr.lookup("InflationResult"),
      manageDataResult: xdr.lookup("ManageDataResult"),
      bumpSeqResult: xdr.lookup("BumpSequenceResult"),
      manageBuyOfferResult: xdr.lookup("ManageBuyOfferResult"),
      pathPaymentStrictSendResult: xdr.lookup("PathPaymentStrictSendResult"),
      createClaimableBalanceResult: xdr.lookup("CreateClaimableBalanceResult"),
      claimClaimableBalanceResult: xdr.lookup("ClaimClaimableBalanceResult"),
      beginSponsoringFutureReservesResult: xdr.lookup(
        "BeginSponsoringFutureReservesResult"
      ),
      endSponsoringFutureReservesResult: xdr.lookup(
        "EndSponsoringFutureReservesResult"
      ),
      revokeSponsorshipResult: xdr.lookup("RevokeSponsorshipResult"),
      clawbackResult: xdr.lookup("ClawbackResult"),
      clawbackClaimableBalanceResult: xdr.lookup(
        "ClawbackClaimableBalanceResult"
      ),
      setTrustLineFlagsResult: xdr.lookup("SetTrustLineFlagsResult"),
      liquidityPoolDepositResult: xdr.lookup("LiquidityPoolDepositResult"),
      liquidityPoolWithdrawResult: xdr.lookup("LiquidityPoolWithdrawResult"),
      invokeHostFunctionResult: xdr.lookup("InvokeHostFunctionResult"),
      extendFootprintTtlResult: xdr.lookup("ExtendFootprintTtlResult"),
      restoreFootprintResult: xdr.lookup("RestoreFootprintResult")
    }
  });
  xdr.union("OperationResult", {
    switchOn: xdr.lookup("OperationResultCode"),
    switchName: "code",
    switches: [
      ["opInner", "tr"],
      ["opBadAuth", xdr.void()],
      ["opNoAccount", xdr.void()],
      ["opNotSupported", xdr.void()],
      ["opTooManySubentries", xdr.void()],
      ["opExceededWorkLimit", xdr.void()],
      ["opTooManySponsoring", xdr.void()]
    ],
    arms: {
      tr: xdr.lookup("OperationResultTr")
    }
  });
  xdr.enum("TransactionResultCode", {
    txFeeBumpInnerSuccess: 1,
    txSuccess: 0,
    txFailed: -1,
    txTooEarly: -2,
    txTooLate: -3,
    txMissingOperation: -4,
    txBadSeq: -5,
    txBadAuth: -6,
    txInsufficientBalance: -7,
    txNoAccount: -8,
    txInsufficientFee: -9,
    txBadAuthExtra: -10,
    txInternalError: -11,
    txNotSupported: -12,
    txFeeBumpInnerFailed: -13,
    txBadSponsorship: -14,
    txBadMinSeqAgeOrGap: -15,
    txMalformed: -16,
    txSorobanInvalid: -17,
    txFrozenKeyAccessed: -18
  });
  xdr.union("InnerTransactionResultResult", {
    switchOn: xdr.lookup("TransactionResultCode"),
    switchName: "code",
    switches: [
      ["txSuccess", "results"],
      ["txFailed", "results"],
      ["txTooEarly", xdr.void()],
      ["txTooLate", xdr.void()],
      ["txMissingOperation", xdr.void()],
      ["txBadSeq", xdr.void()],
      ["txBadAuth", xdr.void()],
      ["txInsufficientBalance", xdr.void()],
      ["txNoAccount", xdr.void()],
      ["txInsufficientFee", xdr.void()],
      ["txBadAuthExtra", xdr.void()],
      ["txInternalError", xdr.void()],
      ["txNotSupported", xdr.void()],
      ["txBadSponsorship", xdr.void()],
      ["txBadMinSeqAgeOrGap", xdr.void()],
      ["txMalformed", xdr.void()],
      ["txSorobanInvalid", xdr.void()],
      ["txFrozenKeyAccessed", xdr.void()]
    ],
    arms: {
      results: xdr.varArray(xdr.lookup("OperationResult"), 2147483647)
    }
  });
  xdr.union("InnerTransactionResultExt", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [[0, xdr.void()]],
    arms: {}
  });
  xdr.struct("InnerTransactionResult", [
    ["feeCharged", xdr.lookup("Int64")],
    ["result", xdr.lookup("InnerTransactionResultResult")],
    ["ext", xdr.lookup("InnerTransactionResultExt")]
  ]);
  xdr.struct("InnerTransactionResultPair", [
    ["transactionHash", xdr.lookup("Hash")],
    ["result", xdr.lookup("InnerTransactionResult")]
  ]);
  xdr.union("TransactionResultResult", {
    switchOn: xdr.lookup("TransactionResultCode"),
    switchName: "code",
    switches: [
      ["txFeeBumpInnerSuccess", "innerResultPair"],
      ["txFeeBumpInnerFailed", "innerResultPair"],
      ["txSuccess", "results"],
      ["txFailed", "results"],
      ["txTooEarly", xdr.void()],
      ["txTooLate", xdr.void()],
      ["txMissingOperation", xdr.void()],
      ["txBadSeq", xdr.void()],
      ["txBadAuth", xdr.void()],
      ["txInsufficientBalance", xdr.void()],
      ["txNoAccount", xdr.void()],
      ["txInsufficientFee", xdr.void()],
      ["txBadAuthExtra", xdr.void()],
      ["txInternalError", xdr.void()],
      ["txNotSupported", xdr.void()],
      ["txBadSponsorship", xdr.void()],
      ["txBadMinSeqAgeOrGap", xdr.void()],
      ["txMalformed", xdr.void()],
      ["txSorobanInvalid", xdr.void()],
      ["txFrozenKeyAccessed", xdr.void()]
    ],
    arms: {
      innerResultPair: xdr.lookup("InnerTransactionResultPair"),
      results: xdr.varArray(xdr.lookup("OperationResult"), 2147483647)
    }
  });
  xdr.union("TransactionResultExt", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [[0, xdr.void()]],
    arms: {}
  });
  xdr.struct("TransactionResult", [
    ["feeCharged", xdr.lookup("Int64")],
    ["result", xdr.lookup("TransactionResultResult")],
    ["ext", xdr.lookup("TransactionResultExt")]
  ]);
  xdr.typedef("Hash", xdr.opaque(32));
  xdr.typedef("Uint256", xdr.opaque(32));
  xdr.typedef("Uint32", xdr.uint());
  xdr.typedef("Int32", xdr.int());
  xdr.typedef("Uint64", xdr.uhyper());
  xdr.typedef("Int64", xdr.hyper());
  xdr.typedef("TimePoint", xdr.lookup("Uint64"));
  xdr.typedef("Duration", xdr.lookup("Uint64"));
  xdr.union("ExtensionPoint", {
    switchOn: xdr.int(),
    switchName: "v",
    switches: [[0, xdr.void()]],
    arms: {}
  });
  xdr.enum("CryptoKeyType", {
    keyTypeEd25519: 0,
    keyTypePreAuthTx: 1,
    keyTypeHashX: 2,
    keyTypeEd25519SignedPayload: 3,
    keyTypeMuxedEd25519: 256
  });
  xdr.enum("PublicKeyType", {
    publicKeyTypeEd25519: 0
  });
  xdr.enum("SignerKeyType", {
    signerKeyTypeEd25519: 0,
    signerKeyTypePreAuthTx: 1,
    signerKeyTypeHashX: 2,
    signerKeyTypeEd25519SignedPayload: 3
  });
  xdr.union("PublicKey", {
    switchOn: xdr.lookup("PublicKeyType"),
    switchName: "type",
    switches: [["publicKeyTypeEd25519", "ed25519"]],
    arms: {
      ed25519: xdr.lookup("Uint256")
    }
  });
  xdr.struct("SignerKeyEd25519SignedPayload", [
    ["ed25519", xdr.lookup("Uint256")],
    ["payload", xdr.varOpaque(64)]
  ]);
  xdr.union("SignerKey", {
    switchOn: xdr.lookup("SignerKeyType"),
    switchName: "type",
    switches: [
      ["signerKeyTypeEd25519", "ed25519"],
      ["signerKeyTypePreAuthTx", "preAuthTx"],
      ["signerKeyTypeHashX", "hashX"],
      ["signerKeyTypeEd25519SignedPayload", "ed25519SignedPayload"]
    ],
    arms: {
      ed25519: xdr.lookup("Uint256"),
      preAuthTx: xdr.lookup("Uint256"),
      hashX: xdr.lookup("Uint256"),
      ed25519SignedPayload: xdr.lookup("SignerKeyEd25519SignedPayload")
    }
  });
  xdr.typedef("Signature", xdr.varOpaque(64));
  xdr.typedef("SignatureHint", xdr.opaque(4));
  xdr.typedef("NodeId", xdr.lookup("PublicKey"));
  xdr.typedef("AccountId", xdr.lookup("PublicKey"));
  xdr.typedef("ContractId", xdr.lookup("Hash"));
  xdr.struct("Curve25519Secret", [["key", xdr.opaque(32)]]);
  xdr.struct("Curve25519Public", [["key", xdr.opaque(32)]]);
  xdr.struct("HmacSha256Key", [["key", xdr.opaque(32)]]);
  xdr.struct("HmacSha256Mac", [["mac", xdr.opaque(32)]]);
  xdr.struct("ShortHashSeed", [["seed", xdr.opaque(16)]]);
  xdr.enum("BinaryFuseFilterType", {
    binaryFuseFilter8Bit: 0,
    binaryFuseFilter16Bit: 1,
    binaryFuseFilter32Bit: 2
  });
  xdr.struct("SerializedBinaryFuseFilter", [
    ["type", xdr.lookup("BinaryFuseFilterType")],
    ["inputHashSeed", xdr.lookup("ShortHashSeed")],
    ["filterSeed", xdr.lookup("ShortHashSeed")],
    ["segmentLength", xdr.lookup("Uint32")],
    ["segementLengthMask", xdr.lookup("Uint32")],
    ["segmentCount", xdr.lookup("Uint32")],
    ["segmentCountLength", xdr.lookup("Uint32")],
    ["fingerprintLength", xdr.lookup("Uint32")],
    ["fingerprints", xdr.varOpaque()]
  ]);
  xdr.typedef("PoolId", xdr.lookup("Hash"));
  xdr.enum("ClaimableBalanceIdType", {
    claimableBalanceIdTypeV0: 0
  });
  xdr.union("ClaimableBalanceId", {
    switchOn: xdr.lookup("ClaimableBalanceIdType"),
    switchName: "type",
    switches: [["claimableBalanceIdTypeV0", "v0"]],
    arms: {
      v0: xdr.lookup("Hash")
    }
  });
  xdr.enum("ScValType", {
    scvBool: 0,
    scvVoid: 1,
    scvError: 2,
    scvU32: 3,
    scvI32: 4,
    scvU64: 5,
    scvI64: 6,
    scvTimepoint: 7,
    scvDuration: 8,
    scvU128: 9,
    scvI128: 10,
    scvU256: 11,
    scvI256: 12,
    scvBytes: 13,
    scvString: 14,
    scvSymbol: 15,
    scvVec: 16,
    scvMap: 17,
    scvAddress: 18,
    scvContractInstance: 19,
    scvLedgerKeyContractInstance: 20,
    scvLedgerKeyNonce: 21
  });
  xdr.enum("ScErrorType", {
    sceContract: 0,
    sceWasmVm: 1,
    sceContext: 2,
    sceStorage: 3,
    sceObject: 4,
    sceCrypto: 5,
    sceEvents: 6,
    sceBudget: 7,
    sceValue: 8,
    sceAuth: 9
  });
  xdr.enum("ScErrorCode", {
    scecArithDomain: 0,
    scecIndexBounds: 1,
    scecInvalidInput: 2,
    scecMissingValue: 3,
    scecExistingValue: 4,
    scecExceededLimit: 5,
    scecInvalidAction: 6,
    scecInternalError: 7,
    scecUnexpectedType: 8,
    scecUnexpectedSize: 9
  });
  xdr.union("ScError", {
    switchOn: xdr.lookup("ScErrorType"),
    switchName: "type",
    switches: [
      ["sceContract", "contractCode"],
      ["sceWasmVm", "code"],
      ["sceContext", "code"],
      ["sceStorage", "code"],
      ["sceObject", "code"],
      ["sceCrypto", "code"],
      ["sceEvents", "code"],
      ["sceBudget", "code"],
      ["sceValue", "code"],
      ["sceAuth", "code"]
    ],
    arms: {
      contractCode: xdr.lookup("Uint32"),
      code: xdr.lookup("ScErrorCode")
    }
  });
  xdr.struct("UInt128Parts", [
    ["hi", xdr.lookup("Uint64")],
    ["lo", xdr.lookup("Uint64")]
  ]);
  xdr.struct("Int128Parts", [
    ["hi", xdr.lookup("Int64")],
    ["lo", xdr.lookup("Uint64")]
  ]);
  xdr.struct("UInt256Parts", [
    ["hiHi", xdr.lookup("Uint64")],
    ["hiLo", xdr.lookup("Uint64")],
    ["loHi", xdr.lookup("Uint64")],
    ["loLo", xdr.lookup("Uint64")]
  ]);
  xdr.struct("Int256Parts", [
    ["hiHi", xdr.lookup("Int64")],
    ["hiLo", xdr.lookup("Uint64")],
    ["loHi", xdr.lookup("Uint64")],
    ["loLo", xdr.lookup("Uint64")]
  ]);
  xdr.enum("ContractExecutableType", {
    contractExecutableWasm: 0,
    contractExecutableStellarAsset: 1
  });
  xdr.union("ContractExecutable", {
    switchOn: xdr.lookup("ContractExecutableType"),
    switchName: "type",
    switches: [
      ["contractExecutableWasm", "wasmHash"],
      ["contractExecutableStellarAsset", xdr.void()]
    ],
    arms: {
      wasmHash: xdr.lookup("Hash")
    }
  });
  xdr.enum("ScAddressType", {
    scAddressTypeAccount: 0,
    scAddressTypeContract: 1,
    scAddressTypeMuxedAccount: 2,
    scAddressTypeClaimableBalance: 3,
    scAddressTypeLiquidityPool: 4
  });
  xdr.struct("MuxedEd25519Account", [
    ["id", xdr.lookup("Uint64")],
    ["ed25519", xdr.lookup("Uint256")]
  ]);
  xdr.union("ScAddress", {
    switchOn: xdr.lookup("ScAddressType"),
    switchName: "type",
    switches: [
      ["scAddressTypeAccount", "accountId"],
      ["scAddressTypeContract", "contractId"],
      ["scAddressTypeMuxedAccount", "muxedAccount"],
      ["scAddressTypeClaimableBalance", "claimableBalanceId"],
      ["scAddressTypeLiquidityPool", "liquidityPoolId"]
    ],
    arms: {
      accountId: xdr.lookup("AccountId"),
      contractId: xdr.lookup("ContractId"),
      muxedAccount: xdr.lookup("MuxedEd25519Account"),
      claimableBalanceId: xdr.lookup("ClaimableBalanceId"),
      liquidityPoolId: xdr.lookup("PoolId")
    }
  });
  xdr.const("SCSYMBOL_LIMIT", 32);
  xdr.typedef("ScVec", xdr.varArray(xdr.lookup("ScVal"), 2147483647));
  xdr.typedef("ScMap", xdr.varArray(xdr.lookup("ScMapEntry"), 2147483647));
  xdr.typedef("ScBytes", xdr.varOpaque());
  xdr.typedef("ScString", xdr.string());
  xdr.typedef("ScSymbol", xdr.string(SCSYMBOL_LIMIT));
  xdr.struct("ScNonceKey", [["nonce", xdr.lookup("Int64")]]);
  xdr.struct("ScContractInstance", [
    ["executable", xdr.lookup("ContractExecutable")],
    ["storage", xdr.option(xdr.lookup("ScMap"))]
  ]);
  xdr.union("ScVal", {
    switchOn: xdr.lookup("ScValType"),
    switchName: "type",
    switches: [
      ["scvBool", "b"],
      ["scvVoid", xdr.void()],
      ["scvError", "error"],
      ["scvU32", "u32"],
      ["scvI32", "i32"],
      ["scvU64", "u64"],
      ["scvI64", "i64"],
      ["scvTimepoint", "timepoint"],
      ["scvDuration", "duration"],
      ["scvU128", "u128"],
      ["scvI128", "i128"],
      ["scvU256", "u256"],
      ["scvI256", "i256"],
      ["scvBytes", "bytes"],
      ["scvString", "str"],
      ["scvSymbol", "sym"],
      ["scvVec", "vec"],
      ["scvMap", "map"],
      ["scvAddress", "address"],
      ["scvContractInstance", "instance"],
      ["scvLedgerKeyContractInstance", xdr.void()],
      ["scvLedgerKeyNonce", "nonceKey"]
    ],
    arms: {
      b: xdr.bool(),
      error: xdr.lookup("ScError"),
      u32: xdr.lookup("Uint32"),
      i32: xdr.lookup("Int32"),
      u64: xdr.lookup("Uint64"),
      i64: xdr.lookup("Int64"),
      timepoint: xdr.lookup("TimePoint"),
      duration: xdr.lookup("Duration"),
      u128: xdr.lookup("UInt128Parts"),
      i128: xdr.lookup("Int128Parts"),
      u256: xdr.lookup("UInt256Parts"),
      i256: xdr.lookup("Int256Parts"),
      bytes: xdr.lookup("ScBytes"),
      str: xdr.lookup("ScString"),
      sym: xdr.lookup("ScSymbol"),
      vec: xdr.option(xdr.lookup("ScVec")),
      map: xdr.option(xdr.lookup("ScMap")),
      address: xdr.lookup("ScAddress"),
      instance: xdr.lookup("ScContractInstance"),
      nonceKey: xdr.lookup("ScNonceKey")
    }
  });
  xdr.struct("ScMapEntry", [
    ["key", xdr.lookup("ScVal")],
    ["val", xdr.lookup("ScVal")]
  ]);
  xdr.enum("ScEnvMetaKind", {
    scEnvMetaKindInterfaceVersion: 0
  });
  xdr.struct("ScEnvMetaEntryInterfaceVersion", [
    ["protocol", xdr.lookup("Uint32")],
    ["preRelease", xdr.lookup("Uint32")]
  ]);
  xdr.union("ScEnvMetaEntry", {
    switchOn: xdr.lookup("ScEnvMetaKind"),
    switchName: "kind",
    switches: [["scEnvMetaKindInterfaceVersion", "interfaceVersion"]],
    arms: {
      interfaceVersion: xdr.lookup("ScEnvMetaEntryInterfaceVersion")
    }
  });
  xdr.struct("ScMetaV0", [
    ["key", xdr.string()],
    ["val", xdr.string()]
  ]);
  xdr.enum("ScMetaKind", {
    scMetaV0: 0
  });
  xdr.union("ScMetaEntry", {
    switchOn: xdr.lookup("ScMetaKind"),
    switchName: "kind",
    switches: [["scMetaV0", "v0"]],
    arms: {
      v0: xdr.lookup("ScMetaV0")
    }
  });
  xdr.const("SC_SPEC_DOC_LIMIT", 1024);
  xdr.enum("ScSpecType", {
    scSpecTypeVal: 0,
    scSpecTypeBool: 1,
    scSpecTypeVoid: 2,
    scSpecTypeError: 3,
    scSpecTypeU32: 4,
    scSpecTypeI32: 5,
    scSpecTypeU64: 6,
    scSpecTypeI64: 7,
    scSpecTypeTimepoint: 8,
    scSpecTypeDuration: 9,
    scSpecTypeU128: 10,
    scSpecTypeI128: 11,
    scSpecTypeU256: 12,
    scSpecTypeI256: 13,
    scSpecTypeBytes: 14,
    scSpecTypeString: 16,
    scSpecTypeSymbol: 17,
    scSpecTypeAddress: 19,
    scSpecTypeMuxedAddress: 20,
    scSpecTypeOption: 1e3,
    scSpecTypeResult: 1001,
    scSpecTypeVec: 1002,
    scSpecTypeMap: 1004,
    scSpecTypeTuple: 1005,
    scSpecTypeBytesN: 1006,
    scSpecTypeUdt: 2e3
  });
  xdr.struct("ScSpecTypeOption", [["valueType", xdr.lookup("ScSpecTypeDef")]]);
  xdr.struct("ScSpecTypeResult", [
    ["okType", xdr.lookup("ScSpecTypeDef")],
    ["errorType", xdr.lookup("ScSpecTypeDef")]
  ]);
  xdr.struct("ScSpecTypeVec", [["elementType", xdr.lookup("ScSpecTypeDef")]]);
  xdr.struct("ScSpecTypeMap", [
    ["keyType", xdr.lookup("ScSpecTypeDef")],
    ["valueType", xdr.lookup("ScSpecTypeDef")]
  ]);
  xdr.struct("ScSpecTypeTuple", [
    ["valueTypes", xdr.varArray(xdr.lookup("ScSpecTypeDef"), 12)]
  ]);
  xdr.struct("ScSpecTypeBytesN", [["n", xdr.lookup("Uint32")]]);
  xdr.struct("ScSpecTypeUdt", [["name", xdr.string(60)]]);
  xdr.union("ScSpecTypeDef", {
    switchOn: xdr.lookup("ScSpecType"),
    switchName: "type",
    switches: [
      ["scSpecTypeVal", xdr.void()],
      ["scSpecTypeBool", xdr.void()],
      ["scSpecTypeVoid", xdr.void()],
      ["scSpecTypeError", xdr.void()],
      ["scSpecTypeU32", xdr.void()],
      ["scSpecTypeI32", xdr.void()],
      ["scSpecTypeU64", xdr.void()],
      ["scSpecTypeI64", xdr.void()],
      ["scSpecTypeTimepoint", xdr.void()],
      ["scSpecTypeDuration", xdr.void()],
      ["scSpecTypeU128", xdr.void()],
      ["scSpecTypeI128", xdr.void()],
      ["scSpecTypeU256", xdr.void()],
      ["scSpecTypeI256", xdr.void()],
      ["scSpecTypeBytes", xdr.void()],
      ["scSpecTypeString", xdr.void()],
      ["scSpecTypeSymbol", xdr.void()],
      ["scSpecTypeAddress", xdr.void()],
      ["scSpecTypeMuxedAddress", xdr.void()],
      ["scSpecTypeOption", "option"],
      ["scSpecTypeResult", "result"],
      ["scSpecTypeVec", "vec"],
      ["scSpecTypeMap", "map"],
      ["scSpecTypeTuple", "tuple"],
      ["scSpecTypeBytesN", "bytesN"],
      ["scSpecTypeUdt", "udt"]
    ],
    arms: {
      option: xdr.lookup("ScSpecTypeOption"),
      result: xdr.lookup("ScSpecTypeResult"),
      vec: xdr.lookup("ScSpecTypeVec"),
      map: xdr.lookup("ScSpecTypeMap"),
      tuple: xdr.lookup("ScSpecTypeTuple"),
      bytesN: xdr.lookup("ScSpecTypeBytesN"),
      udt: xdr.lookup("ScSpecTypeUdt")
    }
  });
  xdr.struct("ScSpecUdtStructFieldV0", [
    ["doc", xdr.string(SC_SPEC_DOC_LIMIT)],
    ["name", xdr.string(30)],
    ["type", xdr.lookup("ScSpecTypeDef")]
  ]);
  xdr.struct("ScSpecUdtStructV0", [
    ["doc", xdr.string(SC_SPEC_DOC_LIMIT)],
    ["lib", xdr.string(80)],
    ["name", xdr.string(60)],
    ["fields", xdr.varArray(xdr.lookup("ScSpecUdtStructFieldV0"), 2147483647)]
  ]);
  xdr.struct("ScSpecUdtUnionCaseVoidV0", [
    ["doc", xdr.string(SC_SPEC_DOC_LIMIT)],
    ["name", xdr.string(60)]
  ]);
  xdr.struct("ScSpecUdtUnionCaseTupleV0", [
    ["doc", xdr.string(SC_SPEC_DOC_LIMIT)],
    ["name", xdr.string(60)],
    ["type", xdr.varArray(xdr.lookup("ScSpecTypeDef"), 2147483647)]
  ]);
  xdr.enum("ScSpecUdtUnionCaseV0Kind", {
    scSpecUdtUnionCaseVoidV0: 0,
    scSpecUdtUnionCaseTupleV0: 1
  });
  xdr.union("ScSpecUdtUnionCaseV0", {
    switchOn: xdr.lookup("ScSpecUdtUnionCaseV0Kind"),
    switchName: "kind",
    switches: [
      ["scSpecUdtUnionCaseVoidV0", "voidCase"],
      ["scSpecUdtUnionCaseTupleV0", "tupleCase"]
    ],
    arms: {
      voidCase: xdr.lookup("ScSpecUdtUnionCaseVoidV0"),
      tupleCase: xdr.lookup("ScSpecUdtUnionCaseTupleV0")
    }
  });
  xdr.struct("ScSpecUdtUnionV0", [
    ["doc", xdr.string(SC_SPEC_DOC_LIMIT)],
    ["lib", xdr.string(80)],
    ["name", xdr.string(60)],
    ["cases", xdr.varArray(xdr.lookup("ScSpecUdtUnionCaseV0"), 2147483647)]
  ]);
  xdr.struct("ScSpecUdtEnumCaseV0", [
    ["doc", xdr.string(SC_SPEC_DOC_LIMIT)],
    ["name", xdr.string(60)],
    ["value", xdr.lookup("Uint32")]
  ]);
  xdr.struct("ScSpecUdtEnumV0", [
    ["doc", xdr.string(SC_SPEC_DOC_LIMIT)],
    ["lib", xdr.string(80)],
    ["name", xdr.string(60)],
    ["cases", xdr.varArray(xdr.lookup("ScSpecUdtEnumCaseV0"), 2147483647)]
  ]);
  xdr.struct("ScSpecUdtErrorEnumCaseV0", [
    ["doc", xdr.string(SC_SPEC_DOC_LIMIT)],
    ["name", xdr.string(60)],
    ["value", xdr.lookup("Uint32")]
  ]);
  xdr.struct("ScSpecUdtErrorEnumV0", [
    ["doc", xdr.string(SC_SPEC_DOC_LIMIT)],
    ["lib", xdr.string(80)],
    ["name", xdr.string(60)],
    ["cases", xdr.varArray(xdr.lookup("ScSpecUdtErrorEnumCaseV0"), 2147483647)]
  ]);
  xdr.struct("ScSpecFunctionInputV0", [
    ["doc", xdr.string(SC_SPEC_DOC_LIMIT)],
    ["name", xdr.string(30)],
    ["type", xdr.lookup("ScSpecTypeDef")]
  ]);
  xdr.struct("ScSpecFunctionV0", [
    ["doc", xdr.string(SC_SPEC_DOC_LIMIT)],
    ["name", xdr.lookup("ScSymbol")],
    ["inputs", xdr.varArray(xdr.lookup("ScSpecFunctionInputV0"), 2147483647)],
    ["outputs", xdr.varArray(xdr.lookup("ScSpecTypeDef"), 1)]
  ]);
  xdr.enum("ScSpecEventParamLocationV0", {
    scSpecEventParamLocationData: 0,
    scSpecEventParamLocationTopicList: 1
  });
  xdr.struct("ScSpecEventParamV0", [
    ["doc", xdr.string(SC_SPEC_DOC_LIMIT)],
    ["name", xdr.string(30)],
    ["type", xdr.lookup("ScSpecTypeDef")],
    ["location", xdr.lookup("ScSpecEventParamLocationV0")]
  ]);
  xdr.enum("ScSpecEventDataFormat", {
    scSpecEventDataFormatSingleValue: 0,
    scSpecEventDataFormatVec: 1,
    scSpecEventDataFormatMap: 2
  });
  xdr.struct("ScSpecEventV0", [
    ["doc", xdr.string(SC_SPEC_DOC_LIMIT)],
    ["lib", xdr.string(80)],
    ["name", xdr.lookup("ScSymbol")],
    ["prefixTopics", xdr.varArray(xdr.lookup("ScSymbol"), 2)],
    ["params", xdr.varArray(xdr.lookup("ScSpecEventParamV0"), 2147483647)],
    ["dataFormat", xdr.lookup("ScSpecEventDataFormat")]
  ]);
  xdr.enum("ScSpecEntryKind", {
    scSpecEntryFunctionV0: 0,
    scSpecEntryUdtStructV0: 1,
    scSpecEntryUdtUnionV0: 2,
    scSpecEntryUdtEnumV0: 3,
    scSpecEntryUdtErrorEnumV0: 4,
    scSpecEntryEventV0: 5
  });
  xdr.union("ScSpecEntry", {
    switchOn: xdr.lookup("ScSpecEntryKind"),
    switchName: "kind",
    switches: [
      ["scSpecEntryFunctionV0", "functionV0"],
      ["scSpecEntryUdtStructV0", "udtStructV0"],
      ["scSpecEntryUdtUnionV0", "udtUnionV0"],
      ["scSpecEntryUdtEnumV0", "udtEnumV0"],
      ["scSpecEntryUdtErrorEnumV0", "udtErrorEnumV0"],
      ["scSpecEntryEventV0", "eventV0"]
    ],
    arms: {
      functionV0: xdr.lookup("ScSpecFunctionV0"),
      udtStructV0: xdr.lookup("ScSpecUdtStructV0"),
      udtUnionV0: xdr.lookup("ScSpecUdtUnionV0"),
      udtEnumV0: xdr.lookup("ScSpecUdtEnumV0"),
      udtErrorEnumV0: xdr.lookup("ScSpecUdtErrorEnumV0"),
      eventV0: xdr.lookup("ScSpecEventV0")
    }
  });
  xdr.typedef("EncodedLedgerKey", xdr.varOpaque());
  xdr.struct("ConfigSettingContractExecutionLanesV0", [
    ["ledgerMaxTxCount", xdr.lookup("Uint32")]
  ]);
  xdr.struct("ConfigSettingContractComputeV0", [
    ["ledgerMaxInstructions", xdr.lookup("Int64")],
    ["txMaxInstructions", xdr.lookup("Int64")],
    ["feeRatePerInstructionsIncrement", xdr.lookup("Int64")],
    ["txMemoryLimit", xdr.lookup("Uint32")]
  ]);
  xdr.struct("ConfigSettingContractParallelComputeV0", [
    ["ledgerMaxDependentTxClusters", xdr.lookup("Uint32")]
  ]);
  xdr.struct("ConfigSettingContractLedgerCostV0", [
    ["ledgerMaxDiskReadEntries", xdr.lookup("Uint32")],
    ["ledgerMaxDiskReadBytes", xdr.lookup("Uint32")],
    ["ledgerMaxWriteLedgerEntries", xdr.lookup("Uint32")],
    ["ledgerMaxWriteBytes", xdr.lookup("Uint32")],
    ["txMaxDiskReadEntries", xdr.lookup("Uint32")],
    ["txMaxDiskReadBytes", xdr.lookup("Uint32")],
    ["txMaxWriteLedgerEntries", xdr.lookup("Uint32")],
    ["txMaxWriteBytes", xdr.lookup("Uint32")],
    ["feeDiskReadLedgerEntry", xdr.lookup("Int64")],
    ["feeWriteLedgerEntry", xdr.lookup("Int64")],
    ["feeDiskRead1Kb", xdr.lookup("Int64")],
    ["sorobanStateTargetSizeBytes", xdr.lookup("Int64")],
    ["rentFee1KbSorobanStateSizeLow", xdr.lookup("Int64")],
    ["rentFee1KbSorobanStateSizeHigh", xdr.lookup("Int64")],
    ["sorobanStateRentFeeGrowthFactor", xdr.lookup("Uint32")]
  ]);
  xdr.struct("ConfigSettingContractLedgerCostExtV0", [
    ["txMaxFootprintEntries", xdr.lookup("Uint32")],
    ["feeWrite1Kb", xdr.lookup("Int64")]
  ]);
  xdr.struct("ConfigSettingContractHistoricalDataV0", [
    ["feeHistorical1Kb", xdr.lookup("Int64")]
  ]);
  xdr.struct("ConfigSettingContractEventsV0", [
    ["txMaxContractEventsSizeBytes", xdr.lookup("Uint32")],
    ["feeContractEvents1Kb", xdr.lookup("Int64")]
  ]);
  xdr.struct("ConfigSettingContractBandwidthV0", [
    ["ledgerMaxTxsSizeBytes", xdr.lookup("Uint32")],
    ["txMaxSizeBytes", xdr.lookup("Uint32")],
    ["feeTxSize1Kb", xdr.lookup("Int64")]
  ]);
  xdr.enum("ContractCostType", {
    wasmInsnExec: 0,
    memAlloc: 1,
    memCpy: 2,
    memCmp: 3,
    dispatchHostFunction: 4,
    visitObject: 5,
    valSer: 6,
    valDeser: 7,
    computeSha256Hash: 8,
    computeEd25519PubKey: 9,
    verifyEd25519Sig: 10,
    vmInstantiation: 11,
    vmCachedInstantiation: 12,
    invokeVmFunction: 13,
    computeKeccak256Hash: 14,
    decodeEcdsaCurve256Sig: 15,
    recoverEcdsaSecp256k1Key: 16,
    int256AddSub: 17,
    int256Mul: 18,
    int256Div: 19,
    int256Pow: 20,
    int256Shift: 21,
    chaCha20DrawBytes: 22,
    parseWasmInstructions: 23,
    parseWasmFunctions: 24,
    parseWasmGlobals: 25,
    parseWasmTableEntries: 26,
    parseWasmTypes: 27,
    parseWasmDataSegments: 28,
    parseWasmElemSegments: 29,
    parseWasmImports: 30,
    parseWasmExports: 31,
    parseWasmDataSegmentBytes: 32,
    instantiateWasmInstructions: 33,
    instantiateWasmFunctions: 34,
    instantiateWasmGlobals: 35,
    instantiateWasmTableEntries: 36,
    instantiateWasmTypes: 37,
    instantiateWasmDataSegments: 38,
    instantiateWasmElemSegments: 39,
    instantiateWasmImports: 40,
    instantiateWasmExports: 41,
    instantiateWasmDataSegmentBytes: 42,
    sec1DecodePointUncompressed: 43,
    verifyEcdsaSecp256r1Sig: 44,
    bls12381EncodeFp: 45,
    bls12381DecodeFp: 46,
    bls12381G1CheckPointOnCurve: 47,
    bls12381G1CheckPointInSubgroup: 48,
    bls12381G2CheckPointOnCurve: 49,
    bls12381G2CheckPointInSubgroup: 50,
    bls12381G1ProjectiveToAffine: 51,
    bls12381G2ProjectiveToAffine: 52,
    bls12381G1Add: 53,
    bls12381G1Mul: 54,
    bls12381G1Msm: 55,
    bls12381MapFpToG1: 56,
    bls12381HashToG1: 57,
    bls12381G2Add: 58,
    bls12381G2Mul: 59,
    bls12381G2Msm: 60,
    bls12381MapFp2ToG2: 61,
    bls12381HashToG2: 62,
    bls12381Pairing: 63,
    bls12381FrFromU256: 64,
    bls12381FrToU256: 65,
    bls12381FrAddSub: 66,
    bls12381FrMul: 67,
    bls12381FrPow: 68,
    bls12381FrInv: 69,
    bn254EncodeFp: 70,
    bn254DecodeFp: 71,
    bn254G1CheckPointOnCurve: 72,
    bn254G2CheckPointOnCurve: 73,
    bn254G2CheckPointInSubgroup: 74,
    bn254G1ProjectiveToAffine: 75,
    bn254G1Add: 76,
    bn254G1Mul: 77,
    bn254Pairing: 78,
    bn254FrFromU256: 79,
    bn254FrToU256: 80,
    bn254FrAddSub: 81,
    bn254FrMul: 82,
    bn254FrPow: 83,
    bn254FrInv: 84,
    bn254G1Msm: 85
  });
  xdr.struct("ContractCostParamEntry", [
    ["ext", xdr.lookup("ExtensionPoint")],
    ["constTerm", xdr.lookup("Int64")],
    ["linearTerm", xdr.lookup("Int64")]
  ]);
  xdr.struct("StateArchivalSettings", [
    ["maxEntryTtl", xdr.lookup("Uint32")],
    ["minTemporaryTtl", xdr.lookup("Uint32")],
    ["minPersistentTtl", xdr.lookup("Uint32")],
    ["persistentRentRateDenominator", xdr.lookup("Int64")],
    ["tempRentRateDenominator", xdr.lookup("Int64")],
    ["maxEntriesToArchive", xdr.lookup("Uint32")],
    ["liveSorobanStateSizeWindowSampleSize", xdr.lookup("Uint32")],
    ["liveSorobanStateSizeWindowSamplePeriod", xdr.lookup("Uint32")],
    ["evictionScanSize", xdr.lookup("Uint32")],
    ["startingEvictionScanLevel", xdr.lookup("Uint32")]
  ]);
  xdr.struct("EvictionIterator", [
    ["bucketListLevel", xdr.lookup("Uint32")],
    ["isCurrBucket", xdr.bool()],
    ["bucketFileOffset", xdr.lookup("Uint64")]
  ]);
  xdr.struct("ConfigSettingScpTiming", [
    ["ledgerTargetCloseTimeMilliseconds", xdr.lookup("Uint32")],
    ["nominationTimeoutInitialMilliseconds", xdr.lookup("Uint32")],
    ["nominationTimeoutIncrementMilliseconds", xdr.lookup("Uint32")],
    ["ballotTimeoutInitialMilliseconds", xdr.lookup("Uint32")],
    ["ballotTimeoutIncrementMilliseconds", xdr.lookup("Uint32")]
  ]);
  xdr.struct("FrozenLedgerKeys", [
    ["keys", xdr.varArray(xdr.lookup("EncodedLedgerKey"), 2147483647)]
  ]);
  xdr.struct("FrozenLedgerKeysDelta", [
    ["keysToFreeze", xdr.varArray(xdr.lookup("EncodedLedgerKey"), 2147483647)],
    [
      "keysToUnfreeze",
      xdr.varArray(xdr.lookup("EncodedLedgerKey"), 2147483647)
    ]
  ]);
  xdr.struct("FreezeBypassTxes", [
    ["txHashes", xdr.varArray(xdr.lookup("Hash"), 2147483647)]
  ]);
  xdr.struct("FreezeBypassTxsDelta", [
    ["addTxes", xdr.varArray(xdr.lookup("Hash"), 2147483647)],
    ["removeTxes", xdr.varArray(xdr.lookup("Hash"), 2147483647)]
  ]);
  xdr.const("CONTRACT_COST_COUNT_LIMIT", 1024);
  xdr.typedef(
    "ContractCostParams",
    xdr.varArray(
      xdr.lookup("ContractCostParamEntry"),
      xdr.lookup("CONTRACT_COST_COUNT_LIMIT")
    )
  );
  xdr.enum("ConfigSettingId", {
    configSettingContractMaxSizeBytes: 0,
    configSettingContractComputeV0: 1,
    configSettingContractLedgerCostV0: 2,
    configSettingContractHistoricalDataV0: 3,
    configSettingContractEventsV0: 4,
    configSettingContractBandwidthV0: 5,
    configSettingContractCostParamsCpuInstructions: 6,
    configSettingContractCostParamsMemoryBytes: 7,
    configSettingContractDataKeySizeBytes: 8,
    configSettingContractDataEntrySizeBytes: 9,
    configSettingStateArchival: 10,
    configSettingContractExecutionLanes: 11,
    configSettingLiveSorobanStateSizeWindow: 12,
    configSettingEvictionIterator: 13,
    configSettingContractParallelComputeV0: 14,
    configSettingContractLedgerCostExtV0: 15,
    configSettingScpTiming: 16,
    configSettingFrozenLedgerKeys: 17,
    configSettingFrozenLedgerKeysDelta: 18,
    configSettingFreezeBypassTxes: 19,
    configSettingFreezeBypassTxsDelta: 20
  });
  xdr.union("ConfigSettingEntry", {
    switchOn: xdr.lookup("ConfigSettingId"),
    switchName: "configSettingId",
    switches: [
      ["configSettingContractMaxSizeBytes", "contractMaxSizeBytes"],
      ["configSettingContractComputeV0", "contractCompute"],
      ["configSettingContractLedgerCostV0", "contractLedgerCost"],
      ["configSettingContractHistoricalDataV0", "contractHistoricalData"],
      ["configSettingContractEventsV0", "contractEvents"],
      ["configSettingContractBandwidthV0", "contractBandwidth"],
      [
        "configSettingContractCostParamsCpuInstructions",
        "contractCostParamsCpuInsns"
      ],
      [
        "configSettingContractCostParamsMemoryBytes",
        "contractCostParamsMemBytes"
      ],
      ["configSettingContractDataKeySizeBytes", "contractDataKeySizeBytes"],
      ["configSettingContractDataEntrySizeBytes", "contractDataEntrySizeBytes"],
      ["configSettingStateArchival", "stateArchivalSettings"],
      ["configSettingContractExecutionLanes", "contractExecutionLanes"],
      ["configSettingLiveSorobanStateSizeWindow", "liveSorobanStateSizeWindow"],
      ["configSettingEvictionIterator", "evictionIterator"],
      ["configSettingContractParallelComputeV0", "contractParallelCompute"],
      ["configSettingContractLedgerCostExtV0", "contractLedgerCostExt"],
      ["configSettingScpTiming", "contractScpTiming"],
      ["configSettingFrozenLedgerKeys", "frozenLedgerKeys"],
      ["configSettingFrozenLedgerKeysDelta", "frozenLedgerKeysDelta"],
      ["configSettingFreezeBypassTxes", "freezeBypassTxes"],
      ["configSettingFreezeBypassTxsDelta", "freezeBypassTxsDelta"]
    ],
    arms: {
      contractMaxSizeBytes: xdr.lookup("Uint32"),
      contractCompute: xdr.lookup("ConfigSettingContractComputeV0"),
      contractLedgerCost: xdr.lookup("ConfigSettingContractLedgerCostV0"),
      contractHistoricalData: xdr.lookup(
        "ConfigSettingContractHistoricalDataV0"
      ),
      contractEvents: xdr.lookup("ConfigSettingContractEventsV0"),
      contractBandwidth: xdr.lookup("ConfigSettingContractBandwidthV0"),
      contractCostParamsCpuInsns: xdr.lookup("ContractCostParams"),
      contractCostParamsMemBytes: xdr.lookup("ContractCostParams"),
      contractDataKeySizeBytes: xdr.lookup("Uint32"),
      contractDataEntrySizeBytes: xdr.lookup("Uint32"),
      stateArchivalSettings: xdr.lookup("StateArchivalSettings"),
      contractExecutionLanes: xdr.lookup(
        "ConfigSettingContractExecutionLanesV0"
      ),
      liveSorobanStateSizeWindow: xdr.varArray(
        xdr.lookup("Uint64"),
        2147483647
      ),
      evictionIterator: xdr.lookup("EvictionIterator"),
      contractParallelCompute: xdr.lookup(
        "ConfigSettingContractParallelComputeV0"
      ),
      contractLedgerCostExt: xdr.lookup("ConfigSettingContractLedgerCostExtV0"),
      contractScpTiming: xdr.lookup("ConfigSettingScpTiming"),
      frozenLedgerKeys: xdr.lookup("FrozenLedgerKeys"),
      frozenLedgerKeysDelta: xdr.lookup("FrozenLedgerKeysDelta"),
      freezeBypassTxes: xdr.lookup("FreezeBypassTxes"),
      freezeBypassTxsDelta: xdr.lookup("FreezeBypassTxsDelta")
    }
  });
  xdr.struct("LedgerCloseMetaBatch", [
    ["startSequence", xdr.lookup("Uint32")],
    ["endSequence", xdr.lookup("Uint32")],
    [
      "ledgerCloseMeta",
      xdr.varArray(xdr.lookup("LedgerCloseMeta"), 2147483647)
    ]
  ]);
});

exports.default = types;
//# sourceMappingURL=curr_generated.js.map
