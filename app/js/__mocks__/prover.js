const initProverModule = async () => {};

class Prover {
  constructor(provingKey, r1cs) {
    this.provingKey = provingKey;
    this.r1cs = r1cs;
    this.num_public_inputs = 2;
    this.num_constraints = 3;
    this.num_wires = 4;
  }

  prove() {
    return { a: 1, b: 2, c: 3 };
  }

  prove_bytes() {
    return new Uint8Array([1, 2, 3]);
  }

  extract_public_inputs() {
    return new Uint8Array([4]);
  }

  verify() {
    return true;
  }

  get_verifying_key() {
    return new Uint8Array([5]);
  }
}

class MerkleTree {
  constructor(depth) {
    this.depth = depth;
  }
}

class MerkleProof {}

function derive_public_key(bytes) {
  return new Uint8Array(bytes);
}

function derive_public_key_hex() {
  return '0xdeadbeef';
}

function compute_commitment() {
  return new Uint8Array([6]);
}

function compute_signature() {
  return new Uint8Array([7]);
}

function compute_nullifier() {
  return new Uint8Array([8]);
}

function poseidon2_hash2() {
  return new Uint8Array([9]);
}

function poseidon2_hash3() {
  return new Uint8Array([10]);
}

function u64_to_field_bytes() {
  return new Uint8Array([11]);
}

function decimal_to_field_bytes() {
  return new Uint8Array([12]);
}

function hex_to_field_bytes() {
  return new Uint8Array([13]);
}

function field_bytes_to_hex() {
  return '0x0d';
}

function verify_proof() {
  return true;
}

function version() {
  return 'mock-version';
}

module.exports = {
  __esModule: true,
  default: initProverModule,
  Prover,
  MerkleTree,
  MerkleProof,
  derive_public_key,
  derive_public_key_hex,
  compute_commitment,
  compute_signature,
  compute_nullifier,
  poseidon2_hash2,
  poseidon2_hash3,
  u64_to_field_bytes,
  decimal_to_field_bytes,
  hex_to_field_bytes,
  field_bytes_to_hex,
  verify_proof,
  version,
};
