#!/usr/bin/env node
/**
 * Convert snarkjs Groth16 outputs into Soroban-friendly formats.
 *
 * Inputs (in build dir):
 *  - proof.json
 *  - public.json
 *  - verification_key.json
 *
 * Outputs (in build dir):
 *  - calldata.txt                 (snarkjs zkesc output)
 *  - proof_soroban.json           {a,b,c} as hex strings (no 0x), sized for BytesN
 *  - public_inputs_hex.json       ["64-hex", ...] for debugging
 *  - public_inputs_decimal.json   ["decimal", ...] for Soroban Vec<u256>
 *  - vk_soroban_fixed.json        {alpha,beta,gamma,delta,ic[]} in Soroban encoding (G2 c1||c0)
 */

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

function die(msg) {
  console.error("soroban_pack:", msg);
  process.exit(1);
}

function padHexToBytes(hex, bytes) {
  const want = bytes * 2;
  hex = hex.toLowerCase();
  if (hex.startsWith("0x")) hex = hex.slice(2);
  if (hex.length > want) die(`hex too long (${hex.length}) want ${want}`);
  return hex.padStart(want, "0");
}

function toHex32FromDecString(s) {
  // s may be decimal string
  const n = BigInt(s);
  if (n < 0n) die("negative field element not allowed");
  let hex = n.toString(16);
  return padHexToBytes(hex, 32);
}

function g1_from_snarkjs(pt) {
  // pt: [x, y, 1]
  const x = toHex32FromDecString(pt[0]);
  const y = toHex32FromDecString(pt[1]);
  return x + y; // 64 bytes => 128 hex chars
}

function g2_from_snarkjs(pt) {
  // snarkjs vk uses pt[0] = [x_re, x_im], pt[1] = [y_re, y_im]
  // Soroban/Ethereum-compatible bytes need Fp2 = c1 || c0 (imag || real)
  const [x_re, x_im] = pt[0];
  const [y_re, y_im] = pt[1];

  return (
      toHex32FromDecString(x_im) +
      toHex32FromDecString(x_re) +
      toHex32FromDecString(y_im) +
      toHex32FromDecString(y_re)
  );
}




function extract0xTokens(text) {
  const m = text.match(/0x[0-9a-fA-F]+/g);
  if (!m) die("no 0x tokens found in calldata");
  return m.map((t) => t.slice(2).toLowerCase());
}

function hexToDecString(hex) {
  hex = hex.toLowerCase();
  if (hex.startsWith("0x")) hex = hex.slice(2);
  if (hex === "") return "0";
  return BigInt("0x" + hex).toString(10);
}

function main() {
  const buildDir = process.argv[2] || "build";
  const proofPath = path.join(buildDir, "proof.json");
  const publicPath = path.join(buildDir, "public.json");
  const vkPath = path.join(buildDir, "verification_key.json");

  if (!fs.existsSync(proofPath)) die(`missing ${proofPath}`);
  if (!fs.existsSync(publicPath)) die(`missing ${publicPath}`);
  if (!fs.existsSync(vkPath)) die(`missing ${vkPath}`);

  // 1) Produce canonical calldata using snarkjs 0.7.x command
  // help says: snarkjs zkesc [public.json] [proof.json]
  let calldata;
  try {
    calldata = execSync(`snarkjs zkesc ${publicPath} ${proofPath}`, { encoding: "utf8" });
  } catch (e) {
    die("failed running `snarkjs zkesc build/public.json build/proof.json` (is snarkjs installed?)");
  }
  fs.writeFileSync(path.join(buildDir, "calldata.txt"), calldata);

  // 2) Parse calldata tokens:
  // a0,a1, b00,b01,b10,b11, c0,c1, then public inputs...
  const toks = extract0xTokens(calldata).map((h) => padHexToBytes(h, 32)); // each 32 bytes
  if (toks.length < 8) die(`calldata has too few tokens: ${toks.length}`);

  const ax = toks[0], ay = toks[1];
  const b00 = toks[2], b01 = toks[3], b10 = toks[4], b11 = toks[5];
  const cx = toks[6], cy = toks[7];

  // proof packing
  const proofSoroban = {
    a: ax + ay,                          // 64 bytes => 128 hex chars
    b: b00 + b01 + b10 + b11,            // 128 bytes => 256 hex chars
    c: cx + cy                           // 64 bytes => 128 hex chars
  };

  fs.writeFileSync(
    path.join(buildDir, "proof_soroban.json"),
    JSON.stringify(proofSoroban, null, 2)
  );

  // public inputs (hex + decimal)
  const pubHex = toks.slice(8); // 32-byte hex strings
  const pubDec = pubHex.map(hexToDecString);

  fs.writeFileSync(path.join(buildDir, "public_inputs_hex.json"), JSON.stringify(pubHex, null, 2));
  fs.writeFileSync(path.join(buildDir, "public_inputs_decimal.json"), JSON.stringify(pubDec, null, 2));

  // 3) Build Soroban VK from snarkjs verification_key.json
  const vk = JSON.parse(fs.readFileSync(vkPath, "utf8"));
  const vkSoroban = {
    alpha: g1_from_snarkjs(vk.vk_alpha_1),
    beta: g2_from_snarkjs(vk.vk_beta_2),
    gamma: g2_from_snarkjs(vk.vk_gamma_2),
    delta: g2_from_snarkjs(vk.vk_delta_2),
    ic: vk.IC.map(g1_from_snarkjs),
  };

  // sanity: ic length should be public_inputs + 1
  if (vkSoroban.ic.length !== pubDec.length + 1) {
    die(
      `IC length mismatch: ic=${vkSoroban.ic.length} but public_inputs=${pubDec.length}; expected ic = public_inputs + 1`
    );
  }

  fs.writeFileSync(
    path.join(buildDir, "vk_soroban_fixed.json"),
    JSON.stringify(vkSoroban, null, 2)
  );

  console.log("✅ Wrote:");
  console.log(` - ${buildDir}/calldata.txt`);
  console.log(` - ${buildDir}/proof_soroban.json`);
  console.log(` - ${buildDir}/public_inputs_decimal.json`);
  console.log(` - ${buildDir}/vk_soroban_fixed.json`);
  console.log("");
  console.log(`Public inputs: ${pubDec.length}`);
  console.log(`IC points:      ${vkSoroban.ic.length}`);
  console.log(`Proof sizes:    a=${proofSoroban.a.length} hex, b=${proofSoroban.b.length} hex, c=${proofSoroban.c.length} hex`);
}

main();
