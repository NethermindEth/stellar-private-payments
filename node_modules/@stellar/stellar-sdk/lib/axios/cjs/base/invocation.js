'use strict';

var buffer = require('buffer');
var asset = require('./asset.js');
var address = require('./address.js');
var scval = require('./scval.js');

function buildInvocationTree(root) {
  const fn = root.function();
  const output = {};
  const inner = fn.value();
  switch (fn.switch().value) {
    // sorobanAuthorizedFunctionTypeContractFn
    case 0: {
      const invokeArgs = fn.contractFn();
      output.type = "execute";
      output.args = {
        source: address.Address.fromScAddress(invokeArgs.contractAddress()).toString(),
        function: invokeArgs.functionName().toString(),
        args: invokeArgs.args().map((arg) => scval.scValToNative(arg))
      };
      break;
    }
    // sorobanAuthorizedFunctionTypeCreateContractHostFn
    // sorobanAuthorizedFunctionTypeCreateContractV2HostFn
    case 1:
    // fallthrough: just no ctor args in V1
    case 2: {
      const createArgs = inner;
      const createV2 = fn.switch().value === 2;
      output.type = "create";
      const createInvocation = {};
      const [exec, preimage] = [
        createArgs.executable(),
        createArgs.contractIdPreimage()
      ];
      if (!!exec.switch().value !== !!preimage.switch().value) {
        throw new Error(
          `creation function appears invalid: ${JSON.stringify(
            inner
          )} (should be wasm+address or token+asset)`
        );
      }
      switch (exec.switch().value) {
        // contractExecutableWasm
        case 0: {
          const details = preimage.fromAddress();
          createInvocation.type = "wasm";
          createInvocation.wasm = {
            salt: buffer.Buffer.from(details.salt()).toString("hex"),
            hash: exec.wasmHash().toString("hex"),
            address: address.Address.fromScAddress(details.address()).toString(),
            // only apply constructor args for WASM+CreateV2 scenario
            ...createV2 && {
              constructorArgs: inner.constructorArgs().map((arg) => scval.scValToNative(arg))
            }
            // empty indicates V2 and no ctor, undefined indicates V1
          };
          break;
        }
        // contractExecutableStellarAsset
        case 1:
          createInvocation.type = "sac";
          createInvocation.asset = asset.Asset.fromOperation(
            preimage.fromAsset()
          ).toString();
          break;
        default:
          throw new Error(`unknown creation type: ${JSON.stringify(exec)}`);
      }
      output.args = createInvocation;
      break;
    }
    default:
      throw new Error(
        `unknown invocation type (${fn.switch().value}): ${JSON.stringify(fn)}`
      );
  }
  output.invocations = root.subInvocations().map((i) => buildInvocationTree(i));
  return output;
}
function walkInvocationTree(root, callback) {
  walkHelper(root, 1, callback);
}
function walkHelper(node, depth, callback, parent) {
  if (callback(node, depth, parent) === false) {
    return;
  }
  node.subInvocations().forEach((i) => walkHelper(i, depth + 1, callback, node));
}

exports.buildInvocationTree = buildInvocationTree;
exports.walkInvocationTree = walkInvocationTree;
//# sourceMappingURL=invocation.js.map
