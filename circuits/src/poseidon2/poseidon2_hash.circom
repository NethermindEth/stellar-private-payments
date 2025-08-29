pragma circom 2.2.2;
// Original circuits from https://github.com/bkomuves/hash-circuits (MIT License)
// Adapted and modified by Nethermind

include "poseidon2_sponge.circom";

//------------------------------------------------------------------------------
// Hash `n` field elements into 1, with approximately 254 bits of preimage security (?)
// (assuming bn128 (or bn254) scalar field. We use capacity=2, rate=1, t=3).

template Poseidon2(n) {
  signal input  inputs[n];
  signal output out;

  component sponge = PoseidonSponge(3,2,n,1);
  sponge.inp    <== inputs;
  sponge.out[0] ==> out;
}

//------------------------------------------------------------------------------