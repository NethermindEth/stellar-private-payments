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

function u64_to_field_bytes() {
  return new Uint8Array([11]);
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
  u64_to_field_bytes,
  version,
};
