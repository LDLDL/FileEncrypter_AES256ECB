//
// Created by yuki on 2020/5/16.
//

#include "pbkdf2.h"

uint8_t *pbkdf2::pbkdf2_8_32_sha256(std::string &pwd, uint64_t iter) {
  uint64_t pwd_len = pwd.size();
  uint64_t _p_len = pwd.size() + 32;

  //temporary array which contains password and salt
  //salt length is 32 * 8 bit
  auto _p = new uint8_t[_p_len];

  //copy password and initial salt to temporary array
  memcpy(_p, pwd.c_str(), pwd_len);
  memcpy((_p + pwd_len), init_salt, 32);

  //calculate U1. U1 = sha256(password + initial salt)
  auto result = sha::sha256_8(_p, _p_len);

  //use U1 as salt then calculate U2. Ui+1 = (password + Ui)
  memcpy((_p + pwd_len), result, 32);

  //calculate n times
  for (int i = 1; i < iter; ++i){
    //calculate Ui+1
    auto _Ui = sha::sha256_8(_p, _p_len);

    //result = U1 xor U2 ... xor Ui
    for (int j = 0; j < 32; ++j){
      result[j] ^= _Ui[j];
    }

    //copy Ui+1 to temporary array as salt then calculate Ui+2
    memcpy((_p + pwd_len), _Ui, 32);
    delete [] _Ui;
  }

  //remember to delete used array
  delete [] _p;
  _p = nullptr;

  return result;
}

uint8_t *pbkdf2::pbkdf2_8_32_sha256(uint8_t *pwd, int pwd_len, uint64_t iter) {
  uint64_t _p_len = pwd_len + 32;

  //temporary array which contains password and salt
  //salt length is 32 * 8 bit
  auto _p = new uint8_t[_p_len];

  //copy password and initial salt to temporary array
  memcpy(_p, pwd, pwd_len);
  memcpy((_p + pwd_len), init_salt, 32);

  //calculate U1. U1 = sha256(password + initial salt)
  auto result = sha::sha256_8(_p, _p_len);

  //use U1 as salt then calculate U2. Ui+1 = (password + Ui)
  memcpy((_p + pwd_len), result, 32);

  //calculate n times
  for (int i = 1; i < iter; ++i){
    //calculate Ui+1
    auto _Ui = sha::sha256_8(_p, _p_len);

    //result = U1 xor U2 ... xor Ui
    for (int j = 0; j < 32; ++j){
      result[j] ^= _Ui[j];
    }

    //copy Ui+1 to temporary array as salt then calculate Ui+2
    memcpy((_p + pwd_len), _Ui, 32);
    delete [] _Ui;
  }

  //remember to delete used array
  delete [] _p;
  _p = nullptr;

  return result;
}

uint32_t *pbkdf2::pbkdf2_32_8_sha256(std::string &pwd, uint64_t iter) {

  auto t = pbkdf2::pbkdf2_8_32_sha256(pwd, iter);
  auto r = new uint32_t[8];

  for (int i = 0; i < 8; ++i){
    r[i] = t[i*4] << 24;
    r[i] |= t[i*4 + 1] << 16;
    r[i] |= t[i*4 + 2] << 8;
    r[i] |= t[i*4 + 3];
  }

  delete [] t;
  t = nullptr;

  return r;
}