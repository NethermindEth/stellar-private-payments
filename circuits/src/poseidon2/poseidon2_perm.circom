pragma circom 2.2.2;

include "poseidon2_const.circom";

//
// The Poseidon2 permutation for BN128/BN254/BN256
//

//------------------------------------------------------------------------------
// The S-box

template SBox() {
  signal input  inp;
  signal output out;

  signal x2 <== inp*inp;
  signal x4 <== x2*x2;

  out <== inp*x4;
}

//------------------------------------------------------------------------------
// partial or internal round

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

//------------------------------------------------------------------------------
// external rounds

template ExternalRound(i, t) {
  signal input  inp[t];
  signal output out[t];

  var round_consts[8][t] = POSEIDON_FULL_ROUNDS(t);

  component sbExt[t];
  for(var j=0; j<t; j++) {
    sbExt[j] = SBox();
    sbExt[j].inp <== inp[j] + round_consts[i][j];
  }
  
  var totalExternal = 0;
  for(var j=0; j<t; j++) {
      totalExternal += sbExt[j].out;
  }
  
  for(var j=0; j<t; j++) {
    out[j] <== totalExternal + sbExt[j].out;
  }

  /*
  out[0] <== 2*sb[0].out +   sb[1].out +   sb[2].out;
  out[1] <==   sb[0].out + 2*sb[1].out +   sb[2].out;
  out[2] <==   sb[0].out +   sb[1].out + 2*sb[2].out;
  */
}

//------------------------------------------------------------------------------
// the initial linear layer

template LinearLayer(t) {
  signal input  inp[t];
  signal output out[t];
  
  var total = 0;
  
  for(var j=0; j<t; j++) {
      total += inp[j];
  }
  
  for(var j=0; j<t; j++) {
    out[j] <== total + inp[j];
  }
  
  /*
      out[0] <== 2*inp[0] +   inp[1] +   inp[2];
      out[1] <==   inp[0] + 2*inp[1] +   inp[2];
      out[2] <==   inp[0] +   inp[1] + 2*inp[2];
  */
}

//------------------------------------------------------------------------------
// the Poseidon2 permutation for t=3

template Permutation(t) {
  signal input  inp[t];
  signal output out[t];

  signal aux[65][t];

  component ll = LinearLayer(t);
  for(var j=0; j<t; j++) { ll.inp[j] <== inp[j];    }
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

  for(var j=0; j<t; j++) { out[j] <== aux[64][j];  log("OUT =", out[j]);}
}

//------------------------------------------------------------------------------
// the "compression function" takes 2 field elements as input and produces
// 1 field element as output. It is a trivial application of the permutation.

template Compression() {
  signal input  inp[2];
  signal output out;

  component perm = Permutation(3);
  perm.inp[0] <== inp[0];
  perm.inp[1] <== inp[1];
  perm.inp[2] <== 0;

  perm.out[0] ==> out;
}

//------------------------------------------------------------------------------