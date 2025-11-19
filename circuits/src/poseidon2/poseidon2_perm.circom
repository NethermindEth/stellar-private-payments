pragma circom 2.2.2;

include "poseidon2_const.circom";


// The Poseidon2 permutation for BN128/BN254/BN256

// The S-box
template SBox() {
  signal input  inp;
  signal output out;

  signal x2 <== inp*inp;
  signal x4 <== x2*x2;

  out <== inp*x4;
}

// Special efficient case for 4x4 matrix multiplication
// Section 5.1 of the Poseidon2 paper (https://eprint.iacr.org/2023/323.pdf)
template MatMul_M4() {
  signal input  inp[4];
  signal output out[4];
  
  signal t_0 <== inp[0] + inp[1];
  signal t_1 <== inp[2] + inp[3];
  signal t_2 <== 2*inp[1] + t_1;
  signal t_3 <== 2*inp[3] + t_0;
  signal t_4 <== 4*t_1 + t_3;
  signal t_5 <== 4*t_0 + t_2;
  signal t_6 <== t_3 + t_5;
  signal t_7 <== t_2 + t_4;
  
  out[0] <== t_6;
  out[1] <== t_5;
  out[2] <== t_7;
  out[3] <== t_4;
}

// Partial or Internal Round
template InternalRound(i, t) {
  signal input  inp[t];
  signal output out[t];

  var round_consts[56] = POSEIDON_PARTIAL_ROUNDS(t);

  component sb = SBox();
  sb.inp <== inp[0] + round_consts[i];
  
  var total = sb.out;
  for(var j=1; j<t; j++) {
      total += inp[j];
  }
  
  var internal_mat[t] = POSEIDON_INTERNAL_MAT_DIAG(t);
  for(var j=0; j<t; j++) {
    if (j == 0) {
      out[j] <== total + sb.out * internal_mat[j];
    } else { 
      out[j] <== total + inp[j] * internal_mat[j];
    }
  }
}

// External (or full) Rounds
template ExternalRound(i, t) {
  signal input  inp[t];
  signal output out[t];

  var round_consts[8][t] = POSEIDON_FULL_ROUNDS(t);

  component sbExt[t];
  for(var j=0; j<t; j++) {
    sbExt[j] = SBox();
    sbExt[j].inp <== inp[j] + round_consts[i][j];
  }
  
  if (t == 4) {
      component m4 = MatMul_M4();
      for(var j=0; j<4; j++) { m4.inp[j] <== sbExt[j].out; }
      for(var j=0; j<4; j++) { out[j] <== m4.out[j]; }
  } else {
      var totalExternal = 0;
      for(var j=0; j<t; j++) {
          totalExternal += sbExt[j].out;
      }
      
      for(var j=0; j<t; j++) {
        out[j] <== totalExternal + sbExt[j].out;
      }
  }
}

// Initial linear layer
template LinearLayer(t) {
  signal input  inp[t];
  signal output out[t];
  
  var total = 0;
  
  for(var j=0; j<t; j++) {
      total += inp[j];
  }
  
  if (t == 4) {
      component m4 = MatMul_M4();
      for(var j=0; j<4; j++) { m4.inp[j] <== inp[j]; }
      for(var j=0; j<4; j++) { out[j] <== m4.out[j]; }
  } else {
      for(var j=0; j<t; j++) {
        out[j] <== total + inp[j];
      }
  }
}

// Poseidon2 permutation
template Permutation(t) {
  signal input  inputs[t];
  signal output out[t];

  signal aux[65][t];

  component ll = LinearLayer(t);
  for(var j=0; j<t; j++) { ll.inp[j] <== inputs[j];    }
  for(var j=0; j<t; j++) { ll.out[j] ==> aux[0][j]; }

  component ext[8];
  for(var k=0; k<8; k++) { ext[k] = ExternalRound(k, t); }
 
  component int[56];
  for(var k=0; k<56; k++) { int[k] = InternalRound(k, t); }

  // first 4 external rounds
  for(var k=0; k<4; k++) {
    for(var j=0; j<t; j++) { ext[k].inp[j] <== aux[k  ][j]; }
    for(var j=0; j<t; j++) { ext[k].out[j] ==> aux[k+1][j]; }
  }

  // the 56 internal rounds
  for(var k=0; k<56; k++) {
    for(var j=0; j<t; j++) { int[k].inp[j] <== aux[k+4][j]; }
    for(var j=0; j<t; j++) { int[k].out[j] ==> aux[k+5][j]; }
  }

  // last 4 external rounds
  for(var k=0; k<4; k++) {
    for(var j=0; j<t; j++) { ext[k+4].inp[j] <== aux[k+60][j]; }
    for(var j=0; j<t; j++) { ext[k+4].out[j] ==> aux[k+61][j]; }
  }

  for(var j=0; j<t; j++) { out[j] <== aux[64][j];}
}