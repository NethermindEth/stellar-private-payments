# Saved plans contain public configuration only. Reject unknown fields.
def text: type == "string" and test("\\S");
def url: type == "string" and test("^https?://[^/@?#\\s]+(/[^?#\\s]*)?$");
def addr($prefix): type == "string" and test("^[" + $prefix + "][A-Z2-7]{55}$");
def amount:
  type == "string" and test("^[0-9]{1,78}$") and
  (sub("^0+"; "") | length > 0 and
    (length < 78 or . < "115792089237316195423570985008687907853269984665640564039457584007913129639936"));
def pubkey:
  type == "object" and keys == ["x", "y"] and
  all(.[]; type == "string" and test("^(0x[0-9a-fA-F]+|[0-9]+)$"));
def pool:
  type == "object" and
  (.kind == "native" or .kind == "classic" or .kind == "contract") and
  (keys == ((["kind", "tokenContractId", "policy", "gvkMode"] +
    (if .kind == "classic" then ["code", "issuer"] else [] end)) | sort)) and
  (.policy | IN("none", "allowlist", "blocklist", "allowlist-blocklist")) and
  (.gvkMode | IN("gvk-off", "gvk-viewonly", "gvk-traceable")) and
  (.tokenContractId | addr("C")) and
  (if .kind == "classic" then
    (.code | type == "string" and test("^[A-Za-z0-9]{1,12}$")) and (.issuer | addr("G"))
  else true end);
type == "object" and
keys == (["version", "network", "networkPassphrase", "rpcUrl", "displayName", "explorerUrl",
  "isTestnet", "deployer", "deployerAddress", "admin", "aspLevels", "poolLevels",
  "maxDeposit", "pools", "gvkAuthorityPubKey"] | sort) and
.version == 1 and
(.network | type == "string" and test("^[A-Za-z0-9_-]+$") and . != "ci-test-network") and
(.networkPassphrase | text) and (.rpcUrl | url) and
(.explorerUrl | . == "" or url) and (.displayName | text) and
(.isTestnet | type == "boolean") and
(.deployer | type == "string" and test("^[A-Za-z0-9_][A-Za-z0-9_.-]*$") and
  (test("^[SG][A-Z2-7]{55}$") | not)) and
(.deployerAddress | addr("G")) and (.admin | addr("GC")) and
.aspLevels == 10 and .poolLevels == 20 and (.maxDeposit | amount) and
(.pools | type == "array" and length > 0 and all(.[]; pool)) and
(if any(.pools[]; .gvkMode != "gvk-off") then (.gvkAuthorityPubKey | pubkey)
 else .gvkAuthorityPubKey == null end)
