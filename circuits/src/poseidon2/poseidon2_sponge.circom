pragma circom 2.2.0;
// Original circuits from https://github.com/bkomuves/hash-circuits (MIT License)
// Adapted and modified by Nethermind

include "poseidon2_perm.circom";

//------------------------------------------------------------------------------

function min(a,b) {
  return (a <= b) ? a : b;
}

//------------------------------------------------------------------------------

//
// Poseidon sponge construction
//
//   t = size of state (currently fixed to 3)
//   c = capacity (1 or 2)
//   r = rate = t - c
//
// everything is measured in number of field elements
//
// we use the padding `10*` from the original Poseidon paper,
// and initial state constant zero. Note that this is different
// from the "SAFE padding" recommended in the Poseidon2 paper
// (which uses `0*` padding and a nontrivial initial state)
//

template PoseidonSponge(t, capacity, input_len, output_len) {

  var rate = t - capacity;

  assert( t == 3);

  assert( capacity > 0 );
  assert( rate     > 0 );
  assert( capacity < t );
  assert( rate     < t );

  signal input  inp[ input_len];
  signal output out[output_len];

  // round up to rate the input + 1 field element ("10*" padding)
  var nblocks    = ((input_len + 1) + (rate-1)) \ rate;
  var nout       = (output_len      + (rate-1)) \ rate;
  var padded_len = nblocks * rate;

  signal padded[padded_len];
  for(var i=0; i<input_len; i++) { padded[i] <== inp[i]; }
  padded[input_len   ] <== 1;
  for(var i=input_len+1; i<padded_len; i++) { padded[i] <== 0; }

  signal state [nblocks+nout][t   ];
  signal sorbed[nblocks     ][rate];

  // domain separation, capacity IV:
  var civ = 2**64 + 256*t + rate;
  log("capacity IV = ",civ);

  // initialize state
  for(var i=0; i<t-1; i++) { state[0][i] <== 0; }
  state[0][t-1] <== civ;

  component absorb [nblocks];
  component squeeze[nout-1];

  for(var m=0; m<nblocks; m++) {

    for(var i=0; i<rate; i++) {
      var a = state [m][i];
      var b = padded[m*rate+i];
      sorbed[m][i] <== a + b;
    }

    absorb[m] = Permutation();
    for(var j=0   ; j<rate; j++) { absorb[m].inp[j] <== sorbed[m][j]; }
    for(var j=rate; j<t   ; j++) { absorb[m].inp[j] <== state [m][j]; }
    absorb[m].out ==> state[m+1];

  }

  var q = min(rate, output_len);
  for(var i=0; i<q; i++) {
    state[nblocks][i] ==> out[i];
  }
  var out_ptr = rate;

  for(var n=1; n<nout; n++) {
    squeeze[n-1] = Permutation();
    squeeze[n-1].inp <== state[nblocks+n-1];
    squeeze[n-1].out ==> state[nblocks+n  ];

    var q = min(rate, output_len-out_ptr);
    for(var i=0; i<q; i++) {
      state[nblocks+n][i] ==> out[out_ptr+i];
    }
    out_ptr += rate;
  }

}

//------------------------------------------------------------------------------

//
// sponge hash with rate=1
//

template Poseidon2_sponge_hash_rate_1(n) {
  signal input  inp[n];
  signal output out;
  component sponge = PoseidonSponge(3, 2, n, 1);
  sponge.inp    <== inp;
  sponge.out[0] ==> out;
}

//
// sponge hash with rate=2
//

template Poseidon2_sponge_hash_rate_2(n) {
  signal input  inp[n];
  signal output out;
  component sponge = PoseidonSponge(3, 1, n, 1);
  sponge.inp    <== inp;
  sponge.out[0] ==> out;
}

//------------------------------------------------------------------------------