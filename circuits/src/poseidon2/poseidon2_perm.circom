pragma circom 2.2.0;

//
// The Poseidon2 permutation for BLS12-381 and t=3
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

template InternalRound(i) {
  signal input  inp[3];
  signal output out[3];

  var round_consts[56] =
    [ 0x5848ebeb5923e92555b7124fffba5d6bd571c6f984195eb9cfd3a3e8eb55b1d4,
      0x270326ee039df19e651e2cfc740628ca634d24fc6e2559f22d8ccbe292efeead,
      0x27c6642ac633bc66dc100fe7fcfa54918af895bce012f182a068fc37c182e274,
      0x1bdfd8b01401c70ad27f57396989129d710e1fb6ab976a459ca18682e26d7ff9,
      0x491b9ba6983bcf9f05fe4794adb44a30879bf8289662e1f57d90f672414e8a4a,
      0x162a14c62f9a89b814b9d6a9c84dd678f4f6fb3f9054d373c832d824261a35ea,
      0x2d193e0f76de586b2af6f79e3127feeaac0a1fc71e2cf0c0f79824667b5b6bec,
      0x46efd8a9a262d6d8fdc9ca5c04b0982f24ddcc6e9863885a6a732a3906a07b95,
      0x509717e0c200e3c92d8dca2973b3db45f0788294351ad07ae75cbb780693a798,
      0x7299b28464a8c94fb9d4df61380f39c0dca9c2c014118789e227252820f01bfc,
      0x044ca3cc4a85d73b81696ef1104e674f4feff82984990ff85d0bf58dc8a4aa94,
      0x1cbaf2b371dac6a81d0453416d3e235cb8d9e2d4f314f46f6198785f0cd6b9af,
      0x1d5b2777692c205b0e6c49d061b6b5f4293c4ab038fdbbdc343e07610f3fede5,
      0x56ae7c7a5293bdc23e85e1698c81c77f8ad88c4b33a5780437ad047c6edb59ba,
      0x2e9bdbba3dd34bffaa30535bdd749a7e06a9adb0c1e6f962f60e971b8d73b04f,
      0x2de11886b18011ca8bd5bae36969299fde40fbe26d047b05035a13661f22418b,
      0x2e07de1780b8a70d0d5b4a3f1841dcd82ab9395c449be947bc998884ba96a721,
      0x0f69f1854d20ca0cbbdb63dbd52dad16250440a99d6b8af3825e4c2bb74925ca,
      0x5dc987318e6e59c1afb87b655dd58cc1d22e513a05838cd4585d04b135b957ca,
      0x48b725758571c9df6c01dc639a85f07297696b1bb678633a29dc91de95ef53f6,
      0x5e565e08c0821099256b56490eaee1d573afd10bb6d17d13ca4e5c611b2a3718,
      0x2eb1b25417fe17670d135dc639fb09a46ce5113507f96de9816c059422dc705e,
      0x115cd0a0643cfb988c24cb44c3fab48aff36c661d26cc42db8b1bdf4953bd82c,
      0x26ca293f7b2c462d066d7378b999868bbb57ddf14e0f958ade801612311d04cd,
      0x4147400d8e1aaccf311a6b5b762011ab3e45326e4d4b9de26992816b99c528ac,
      0x6b0db7dccc4ba1b268f6bdcc4d372848d4a72976c268ea30519a2f73e6db4d55,
      0x17bf1b93c4c7e01a2a830aa162412cd90f160bf9f71e967ff5209d14b24820ca,
      0x4b431cd9efedbc94cf1eca6f9e9c1839d0e66a8bffa8c8464cac81a39d3cf8f1,
      0x35b41a7ac4f3c571a24f8456369c85dfe03c0354bd8cfd3805c86f2e7dc293c5,
      0x3b1480080523c439435927994849bea964e14d3beb2dddde72ac156af435d09e,
      0x2cc6810031dc1b0d4950856dc907d57508e286442a2d3eb2271618d874b14c6d,
      0x6f4141c8401c5a395ba6790efd71c70c04afea06c3c92826bcabdd5cb5477d51,
      0x25bdbbeda1bde8c1059618e2afd2ef999e517aa93b78341d91f318c09f0cb566,
      0x392a4a8758e06ee8b95f33c25dde8ac02a5ed0a27b61926cc6313487073f7f7b,
      0x272a55878a08442b9aa6111f4de009485e6a6fd15db89365e7bbcef02eb5866c,
      0x631ec1d6d28dd9e824ee89a30730aef7ab463acfc9d184b355aa05fd6938eab5,
      0x4eb6fda10fd0fbde02c7449bfbddc35bcd8225e7e5c3833a0818a100409dc6f2,
      0x2d5b308b0cf02cdfefa13c4e60e26239a6ebba011694dd129b925b3c5b21e0e2,
      0x16549fc6af2f3b72dd5d293d72e2e5f244dff42f18b46c56ef38c57c311673ac,
      0x42332677ff359c5e8db836d9f5fb54822e39bd5e22340bb9ba975ba1a92be382,
      0x49d7d2c0b449e5179bc5ccc3b44c6075d9849b5610465f09ea725ddc97723a94,
      0x64c20fb90d7a003831757cc4c6226f6e4985fc9ecb416b9f684ca0351d967904,
      0x59cff40de83b52b41bc443d7979510d771c940b9758ca820fe73b5c8d5580934,
      0x53db2731730c39b04edd875fe3b7c882808285cdbc621d7af4f80dd53ebb71b0,
      0x1b10bb7a82afce39fa69c3a2ad52f76d76398265344203119b7126d9b46860df,
      0x561b6012d666bfe179c4dd7f84cdd1531596d3aac7c5700ceb319f91046a63c9,
      0x0f1e7505ebd91d2fc79c2df7dc98a3bed1b36968ba0405c090d27f6a00b7dfc8,
      0x2f313faf0d3f6187537a7497a3b43f46797fd6e3f18eb1caff457756b819bb20,
      0x3a5cbb6de450b481fa3ca61c0ed15bc55cad11ebf0f7ceb8f0bc3e732ecb26f6,
      0x681d93411bf8ce63f6716aefbd0e24506454c0348ee38fabeb264702714ccf94,
      0x5178e940f50004312646b436727f0e80a7b8f2e9ee1fdc677c4831a7672777fb,
      0x3dab54bc9bef688dd92086e253b439d651baa6e20f892b62865527cbca915982,
      0x4b3ce75311218f9ae905f84eaa5b2b3818448bbf3972e1aad69de321009015d0,
      0x06dbfb42b979884de280d31670123f744c24b33b410fefd4368045acf2b71ae3,
      0x068d6b4608aae810c6f039ea1973a63eb8d2de72e3d2c9eca7fc32d22f18b9d3,
      0x4c5c254589a92a36084a57d3b1d964278acc7e4fe8f69f2955954f27a79cebef
    ];

  component sb = SBox();
  sb.inp <== inp[0] + round_consts[i];

  out[0] <== 2*sb.out +   inp[1] +   inp[2];
  out[1] <==   sb.out + 2*inp[1] +   inp[2];
  out[2] <==   sb.out +   inp[1] + 3*inp[2];

}

//------------------------------------------------------------------------------
// external rounds

template ExternalRound(i) {
  signal input  inp[3];
  signal output out[3];

  var round_consts[8][3] =

    [ [ 0x6f007a551156b3a449e44936b7c093644a0ed33f33eaccc628e942e836c1a875,
        0x360d7470611e473d353f628f76d110f34e71162f31003b7057538c2596426303,
        0x4b5fec3aa073df44019091f007a44ca996484965f7036dce3e9d0977edcdc0f6
      ]
    , [0x67cf1868af6396c0b84cce715e539f849e06cd1c383ac5b06100c76bcc973a11,
       0x555db4d1dced819f5d3de70fde83f1c7d3e8c98968e516a23a771a5c9c8257aa,
       0x2bab94d7ae222d135dc3c6c5febfaa314908ac2f12ebe06fbdb74213bf63188b
      ]
    , [ 0x66f44be5296682c4fa7882799d6dd049b6d7d2c950ccf98cf2e50d6d1ebb77c2,
        0x150c93fef652fb1c2bf03e1a29aa871fef77e7d736766c5d0939d92753cc5dc8,
        0x3270661e68928b3a955d55db56dc57c103cc0a60141e894e14259dce537782b2
      ]
    , [ 0x073f116f04122e25a0b7afe4e2057299b407c370f2b5a1ccce9fb9ffc345afb3,
        0x409fda22558cfe4d3dd8dce24f69e76f8c2aaeb1dd0f09d65e654c71f32aa23f,
        0x2a32ec5c4ee5b1837affd09c1f53f5fd55c9cd2061ae93ca8ebad76fc71554d8
      ]

    , [ 0x6cbac5e1700984ebc32da15b4bb9683faabab55f67ccc4f71d9560b3475a77eb,
        0x4603c403bbfa9a17738a5c6278eaab1c37ec30b0737aa2409fc4898069eb983c,
        0x6894e7e22b2c1d5c70a712a6345ae6b192a9c833a9234c31c56aacd16bc2f100
      ]
    , [ 0x5be2cbbc44053ad08afa4d1eabc7f3d231eea799b93f226e905b7d4d65c58ebb,
        0x58e55f287b453a9808624a8c2a353d528da0f7e713a5c6d0d7711e47063fa611,
        0x366ebfafa3ad381c0ee258c9b8fdfccdb868a7d7e1f1f69a2b5dfcc5572555df
      ]
    , [ 0x45766ab728968c642f90d97ccf5504ddc10518a819ebbcc4d09c3f5d784d67ce,
        0x39678f65512f1ee404db3024f41d3f567ef66d89d044d022e6bc229e95bc76b1,
        0x463aed1d2f1f955e3078be5bf7bfc46fc0eb8c51551906a8868f18ffae30cf4f
      ]
    , [ 0x21668f016a8063c0d58b7750a3bc2fe1cf82c25f99dc01a4e534c88fe53d85fe,
        0x39d00994a8a5046a1bc749363e98a768e34dea56439fe1954bef429bc5331608,
        0x4d7f5dcd78ece9a933984de32c0b48fac2bba91f261996b8e9d1021773bd07cc
      ]
    ];

  component sb[3];
  for(var j=0; j<3; j++) {
    sb[j] = SBox();
    sb[j].inp <== inp[j] + round_consts[i][j];
  }

  out[0] <== 2*sb[0].out +   sb[1].out +   sb[2].out;
  out[1] <==   sb[0].out + 2*sb[1].out +   sb[2].out;
  out[2] <==   sb[0].out +   sb[1].out + 2*sb[2].out;
}

//------------------------------------------------------------------------------
// the initial linear layer

template LinearLayer() {
  signal input  inp[3];
  signal output out[3];
  out[0] <== 2*inp[0] +   inp[1] +   inp[2];
  out[1] <==   inp[0] + 2*inp[1] +   inp[2];
  out[2] <==   inp[0] +   inp[1] + 2*inp[2];
}

//------------------------------------------------------------------------------
// the Poseidon2 permutation for t=3

template Permutation() {
  signal input  inp[3];
  signal output out[3];

  signal aux[65][3];

  component ll = LinearLayer();
  for(var j=0; j<3; j++) { ll.inp[j] <== inp[j];    }
  for(var j=0; j<3; j++) { ll.out[j] ==> aux[0][j]; }

  component ext[8];
  for(var k=0; k<8; k++) { ext[k] = ExternalRound(k); }

  component int[56];
  for(var k=0; k<56; k++) { int[k] = InternalRound(k); }

  // first 4 external rounds
  for(var k=0; k<4; k++) {
    for(var j=0; j<3; j++) { ext[k].inp[j] <== aux[k  ][j]; }
    for(var j=0; j<3; j++) { ext[k].out[j] ==> aux[k+1][j]; }
  }

  // the 56 internal rounds
  for(var k=0; k<56; k++) {
    for(var j=0; j<3; j++) { int[k].inp[j] <== aux[k+4][j]; }
    for(var j=0; j<3; j++) { int[k].out[j] ==> aux[k+5][j]; }
  }

  // last 4 external rounds
  for(var k=0; k<4; k++) {
    for(var j=0; j<3; j++) { ext[k+4].inp[j] <== aux[k+60][j]; }
    for(var j=0; j<3; j++) { ext[k+4].out[j] ==> aux[k+61][j]; }
  }

  for(var j=0; j<3; j++) { out[j] <== aux[64][j]; }
}

//------------------------------------------------------------------------------
// the "compression function" takes 2 field elements as input and produces
// 1 field element as output. It is a trivial application of the permutation.

template Compression() {
  signal input  inp[2];
  signal output out;

  component perm = Permutation();
  perm.inp[0] <== inp[0];
  perm.inp[1] <== inp[1];
  perm.inp[2] <== 0;

  perm.out[0] ==> out;
}

//------------------------------------------------------------------------------