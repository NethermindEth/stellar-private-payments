pragma circom 2.2.2;

include "poseidon2_perm.circom";

// Please note that we expose ONLY fixed-sized hashes.
// As it is common for most ZK applications (e.g. the default implementation for Poseidon1 in circomlib)
// We do not provide the full sponge construction, but it can be built from the exposed permutation.
template Poseidon2(n) {
  signal input inputs[n];
  signal input domainSeparation; // Additional capacity bit
  signal output out;
  
  component perm = Permutation(n + 1);
  
  // Load inputs
  for(var i=0; i<n; i++) {
    perm.inputs[i] <== inputs[i];
  }
  perm.inputs[n] <== domainSeparation;
  
  // Get permutation output
  perm.out[0] ==> out;
}
