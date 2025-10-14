pragma circom 2.2.2;

include "poseidon2_perm.circom";

// Please note that we expose ONLY the permutation argument.
// As it is common for most ZK applications (e.g. the default implementation for Poseidon1 in circomlib)
// We do not provide the full sponge construction, but it can be build from the permutation.
template Poseidon2(n) {
  signal input inputs[n];
  signal output out;
  
  component perm = Permutation(n);
  perm.inp    <== inputs;
  perm.out[0] ==> out;
}