//
// Created by yuki on 2020/5/17.
//

#include <iostream>
#include "aes256.h"

using namespace aes;

void AES256ECB::key_expansion() {
  //create expanded key array
  e_key = new uint8_t[e_key_length];
  //first 32 char of expanded key is the key itself
  memcpy(e_key, key, key_length);

  /// \note W(8i)   = g(W(8i-1)) xor W(8i-8)
  ///       W(8i+1) = W(8i)      xor W(8i-7)
  ///       W(8i+2) = W(8i+1)    xor W(8i-6)
  ///       W(8i+3) = W(8i+2)    xor W(8i-5)
  ///       W(8i+4) = h(W(8i-3)) xor W(8i-4)
  ///       W(8i+5) = W(8i+4)    xor W(8i-3)
  ///       W(8i+6) = W(8i+5)    xor W(8i-2)
  ///       W(8i+7) = W(8i+6)    xor W(8i-1)
  ///       the length of one W is 32bits
  ///       a round of aes256 need 4 W
  ///       total 60 W
  for(unsigned int i = key_length / 4; i < 4 * (round_times + 1); ++i){
    //temp array
    uint8_t _t[4];
    // copy Wi-1 to temp array
    memcpy(_t, e_key + (i - 1) * 4, 4);

    //g func
    if (i % 8 == 0){
      //rot word
      uint8_t __t = _t[0];
      _t[0] = _t[1];
      _t[1] = _t[2];
      _t[2] = _t[3];
      _t[3] = __t;

      //sbox replace
      _t[0] = sbox[_t[0]];
      _t[1] = sbox[_t[1]];
      _t[2] = sbox[_t[2]];
      _t[3] = sbox[_t[3]];

      // xor
      _t[0] = _t[0] ^ rcon[i/8];
    }

    //h func
    if (i % 8 == 4){
      //sbox replace
      _t[0] = sbox[_t[0]];
      _t[1] = sbox[_t[1]];
      _t[2] = sbox[_t[2]];
      _t[3] = sbox[_t[3]];
    }

    e_key[i * 4 + 0] = e_key[(i - 8) * 4 + 0] ^ _t[0];
    e_key[i * 4 + 1] = e_key[(i - 8) * 4 + 1] ^ _t[1];
    e_key[i * 4 + 2] = e_key[(i - 8) * 4 + 2] ^ _t[2];
    e_key[i * 4 + 3] = e_key[(i - 8) * 4 + 3] ^ _t[3];
  }
}

inline void AES256ECB::SubBytes(uint8_t *msg) {
  for(int i = 0; i < 16; ++i){
    msg[i] = sbox[msg[i]];
  }
}

inline void AES256ECB::InvSubBytes(uint8_t *ctxt) {
  for(int i = 0; i < 16; ++i){
    ctxt[i] = inv_sbox[ctxt[i]];
  }
}

inline void AES256ECB::ShiftRows(uint8_t *msg) {
  uint8_t _t;

  // Rotate first row 1 columns to left
  _t = MIJ(msg, 0, 1);
  MIJ(msg, 0, 1) = MIJ(msg, 1, 1);
  MIJ(msg, 1, 1) = MIJ(msg, 2, 1);
  MIJ(msg, 2, 1) = MIJ(msg, 3, 1);
  MIJ(msg, 3, 1) = _t;

  // Rotate second row 2 columns to left
  _t = MIJ(msg, 0, 2);
  MIJ(msg, 0, 2) = MIJ(msg, 2, 2);
  MIJ(msg, 2, 2) = _t;

  _t = MIJ(msg, 1, 2);
  MIJ(msg, 1, 2) = MIJ(msg, 3, 2);
  MIJ(msg, 3, 2) = _t;

  // Rotate third row 3 columns to left
  _t = MIJ(msg, 0, 3);
  MIJ(msg, 0, 3) = MIJ(msg, 3, 3);
  MIJ(msg, 3, 3) = MIJ(msg, 2, 3);
  MIJ(msg, 2, 3) = MIJ(msg, 1, 3);
  MIJ(msg, 1, 3) = _t;
}

inline void AES256ECB::InvShiftRows(uint8_t *ctxt) {
  uint8_t _t;

  // Rotate first row 1 columns to left
  _t = MIJ(ctxt, 3, 1);
  MIJ(ctxt, 3, 1) = MIJ(ctxt, 2, 1);
  MIJ(ctxt, 2, 1) = MIJ(ctxt, 1, 1);
  MIJ(ctxt, 1, 1) = MIJ(ctxt, 0, 1);
  MIJ(ctxt, 0, 1) = _t;

  // Rotate second row 2 columns to right
  _t = MIJ(ctxt, 0, 2);
  MIJ(ctxt, 0, 2) = MIJ(ctxt, 2, 2);
  MIJ(ctxt, 2, 2) = _t;

  _t = MIJ(ctxt, 1, 2);
  MIJ(ctxt, 1, 2) = MIJ(ctxt, 3, 2);
  MIJ(ctxt, 3, 2) = _t;

  // Rotate third row 3 columns to right
  _t = MIJ(ctxt, 0, 3);
  MIJ(ctxt, 0, 3) = MIJ(ctxt, 1, 3);
  MIJ(ctxt, 1, 3) = MIJ(ctxt, 2, 3);
  MIJ(ctxt, 2, 3) = MIJ(ctxt, 3, 3);
  MIJ(ctxt, 3, 3) = _t;
}

//Mix Columns calculate func
inline uint8_t xtime(uint8_t x){
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

inline void AES256ECB::MixColumns(uint8_t *msg) {
  uint8_t Tmp, Tm, t;

  for (int i = 0; i < 4; ++i){
    t   = MIJ(msg, i, 0);
    Tmp = MIJ(msg, i, 0) ^ MIJ(msg, i, 1) ^ MIJ(msg, i, 2) ^ MIJ(msg, i, 3) ;

    Tm  = MIJ(msg, i, 0) ^ MIJ(msg, i, 1) ;
    Tm = xtime(Tm);
    MIJ(msg, i, 0) ^= Tm ^ Tmp ;

    Tm  = MIJ(msg, i, 1) ^ MIJ(msg, i, 2) ;
    Tm = xtime(Tm);
    MIJ(msg, i, 1) ^= Tm ^ Tmp ;

    Tm  = MIJ(msg, i, 2) ^ MIJ(msg, i, 3) ;
    Tm = xtime(Tm);
    MIJ(msg, i, 2) ^= Tm ^ Tmp ;

    Tm  = MIJ(msg, i, 3) ^ t ;
    Tm = xtime(Tm);
    MIJ(msg, i, 3) ^= Tm ^ Tmp ;
  }
}

inline void AES256ECB::InvMixColumns(uint8_t *ctxt) {
  uint8_t a, b, c, d;

  for (int i = 0; i < 4; ++i){
    a = MIJ(ctxt, i, 0);
    b = MIJ(ctxt, i, 1);
    c = MIJ(ctxt, i, 2);
    d = MIJ(ctxt, i, 3);

    MIJ(ctxt, i, 0) = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
    MIJ(ctxt, i, 1) = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
    MIJ(ctxt, i, 2) = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
    MIJ(ctxt, i, 3) = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
  }
}

inline void AES256ECB::RoundKeyAdd(uint8_t *msg, int round) {
  for(int i = 0; i < 4; ++i){
    for(int j = 0; j < 4; ++j){
      MIJ(msg, i, j) ^= e_key[(round * 16) + (i * 4) + j];
    }
  }
}

AES256ECB::AES256ECB(std::string &pwd) {
  //use pbkdf2 to convert password to 256bit key
  key = pbkdf2_8_32_sha256(pwd, 1024);
  // expand key
  key_expansion();
}

AES256ECB::~AES256ECB(){
  //clear memory
  delete [] key;
  key = nullptr;

  delete [] e_key;
  e_key = nullptr;
}

int AES256ECB::encrypt(uint8_t *msg) {

  //0 round
  RoundKeyAdd(msg, 0);

  // 1 - 13 round
  for(int i = 1; i < 14 ; ++i){
    SubBytes(msg);

    ShiftRows(msg);

    MixColumns(msg);

    RoundKeyAdd(msg, i);
  }

  //last round
  SubBytes(msg);

  ShiftRows(msg);

  RoundKeyAdd(msg, 14);

  return 16;
}

int AES256ECB::decrypt(uint8_t *ctxt) {

  RoundKeyAdd(ctxt, 14);

  for(int i = 13; i > 0; --i){
    InvShiftRows(ctxt);

    InvSubBytes(ctxt);

    RoundKeyAdd(ctxt, i);

    InvMixColumns(ctxt);
  }

  InvShiftRows(ctxt);

  InvSubBytes(ctxt);

  RoundKeyAdd(ctxt, 0);

  return 16;
}
