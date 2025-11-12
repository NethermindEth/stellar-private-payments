pragma circom 2.2.2;

include "poseidon2_perm.circom";

template PoseidonCompress() {
  signal input inputs[2];   // Compress is optimized for 2 inputs, thinking of internal node hashing of binary merkle trees.
  signal output out;
  signal compression[2];
  
  // Compute P(x)
  component perm = Permutation(2);
  perm.inputs <== inputs;
  
  // Compute (P(x) + x)
  for (var i = 0; i < 2; i++) {
    compression[i] <== perm.out[i] + inputs[i];
  }
      
  // Get compression output
  compression[0] ==> out;
}