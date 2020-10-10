//
// Created by yuki on 2020/5/16.
//
#include "sha256.h"

static inline uint32_t sha::_ma(uint32_t x, uint32_t y, uint32_t z){
  return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t sha::_ch(uint32_t x, uint32_t y, uint32_t z){
  return (x & y) ^ ((~x) & z);
}

static inline uint32_t sha::_bsig0(uint32_t x){
  return std::rotr(x,2) ^ std::rotr(x,13) ^ std::rotr(x,22);
}

static inline uint32_t sha::_bsig1(uint32_t x){
  return std::rotr(x,6) ^ std::rotr(x,11) ^ std::rotr(x,25);
}

static inline uint32_t sha::_ssig0(uint32_t x){
  return std::rotr(x,7) ^ std::rotr(x,18) ^ (x >> 3);
}

static inline uint32_t sha::_ssig1(uint32_t x){
  return std::rotr(x,17) ^ std::rotr(x,19) ^ (x >> 10);
}

inline void sha::_sha256_calculate(const uint8_t *msg, uint32_t *result){
  uint32_t a0, b1, c2, d3, e4, f5, g6, h7;
  uint32_t t1, t2;
  uint32_t w[64];

  int j = 0;

  //make 64 words
  for (int i = 0; i < 16; ++i, j+=4)
    w[i] = msg[j]<<24 | msg[j+1]<<16 | msg[j+2]<<8 | msg[j+3];
  for (int i = 16; i < 64; ++i)
    w[i] = _ssig1(w[i-2]) + w[i-7] + _ssig0(w[i-15]) + w[i-16];

  //copy last block values
  //if this is first block, the values will be hash initial values
  a0 = result[0];
  b1 = result[1];
  c2 = result[2];
  d3 = result[3];
  e4 = result[4];
  f5 = result[5];
  g6 = result[6];
  h7 = result[7];

  //calculate
  for (int i = 0; i < 64; ++i){
    t1 = h7 + _bsig1(e4) + _ch(e4,f5,g6) + hconst[i] + w[i];
    t2 = _bsig0(a0) + _ma(a0,b1,c2);

    h7 = g6;
    g6 = f5;
    f5 = e4;
    e4 = d3 + t1;
    d3 = c2;
    c2 = b1;
    b1 = a0;
    a0 = t1 + t2;
  }

  //add this block values to last block values
  result[0] += a0;
  result[1] += b1;
  result[2] += c2;
  result[3] += d3;
  result[4] += e4;
  result[5] += f5;
  result[6] += g6;
  result[7] += h7;
}

uint32_t *sha::sha256(uint8_t *msg, uint64_t len) {
  uint64_t n = len % SHA256_BLOCK_SIZE;
  uint64_t block_n = (len / SHA256_BLOCK_SIZE) + ((n < 56) ? 1 : 2);
  uint64_t _msg_len = block_n * SHA256_BLOCK_SIZE;

  //create temp space
  auto _msg = new uint8_t[_msg_len]{0};

  //copy memory
  memcpy(_msg, msg, len);

  //add needed message
  _msg[len] = 0x80;

  //set original message length
  for(int i = 0; i < 8; ++i)
    _msg[block_n * SHA256_BLOCK_SIZE - 1 - i] = ((len*8) >> i*8) & 0xff;

  //create a array to store result
  auto result = new uint32_t[8];

  //set hash initial value to result array
  for (int i = 0; i < 8; i++)
    result[i] = hinit[i];

  //_mp is a pointer which point to the first element of message block
  auto _mp = _msg;
  for (int i = 0; i < block_n; ++i){
    //calculate this block
    _sha256_calculate(_mp, result);
    //_mp point to the next block
    _mp += SHA256_BLOCK_SIZE;
  }
  _mp = nullptr;

  delete [] _msg;
  _msg = nullptr;

  return result;
}

uint32_t *sha::sha256(std::string &msg) {
  uint64_t len = msg.size();
  uint64_t n = len % SHA256_BLOCK_SIZE;
  uint64_t block_n = (len / SHA256_BLOCK_SIZE) + ((n < 56) ? 1 : 2);
  uint64_t _msg_len = block_n * SHA256_BLOCK_SIZE;

  //create temp space
  auto _msg = new uint8_t[_msg_len]{0};

  //copy memory
  memcpy(_msg, msg.c_str(), len);

  //add needed message
  _msg[len] = 0x80;

  //set original message length to the last 64bit of last block
  for(int i = 0; i < 8; ++i){
    _msg[block_n * SHA256_BLOCK_SIZE - 1 - i] = ((len*8) >> i*8) & 0xff;
  }

  //create a array to store result
  auto result = new uint32_t[8];

  //set hash initial value to result array
  for (int i = 0; i < 8; i++)
    result[i] = hinit[i];

  //_mp is a pointer which point to the first element of message block
  auto _mp = _msg;
  for (int i = 0; i < block_n; ++i){
    //calculate this block
    _sha256_calculate(_mp, result);
    //_mp point to the next block
    _mp += SHA256_BLOCK_SIZE;
  }
  _mp = nullptr;

  delete [] _msg;
  _msg = nullptr;

  return result;
}

uint8_t *sha::sha256_8(uint8_t *msg, uint64_t len) {
  auto _r = sha::sha256(msg, len);

  auto result = new uint8_t[32];

  // put 8 uint32_t values into 32 uint8_t array
  for (int i = 0; i < 8; ++i){
    result[i*4 + 3] = _r[i];
    result[i*4 + 2] = _r[i] >> 8;
    result[i*4 + 1] = _r[i] >> 16;
    result[i*4] = _r[i] >> 24;
  }

  delete [] _r;
  _r = nullptr;

  return result;
}

uint8_t *sha::sha256_8(std::string &msg) {
  auto _r = sha::sha256(msg);

  auto result = new uint8_t[32];

  // put 8 uint32_t values into 32 uint8_t array
  for (int i = 0; i < 8; ++i){
    result[i*4 + 3] = _r[i];
    result[i*4 + 2] = _r[i] >> 8;
    result[i*4 + 1] = _r[i] >> 16;
    result[i*4] = _r[i] >> 24;
  }

  delete [] _r;
  _r = nullptr;

  return result;
}

sha::sha256_stream::sha256_stream(uint64_t stream_size) {
  this->result = new uint32_t[8];
  this->stream_size = stream_size;

  //set hash initial value to result array
  for (int i = 0; i < 8; i++)
    result[i] = hinit[i];
}

sha::sha256_stream::~sha256_stream() {
  delete [] result;
  result = nullptr;
}

bool sha::sha256_stream::stream_add(uint8_t *msg, uint64_t len) {
  if(len == SHA256_BLOCK_SIZE){
    sha::_sha256_calculate(msg, this->result);
    return true;
  }
  else{
    return false;
  }
}

bool sha::sha256_stream::stream_last_block(uint8_t *msg, uint64_t len) {
  if(len == SHA256_BLOCK_SIZE){
    _sha256_calculate(msg, this->result);

    auto _msg = new uint8_t[SHA256_BLOCK_SIZE]{0};
    _msg[0] = 0x80;

    //set original message length
    for(int i = 0; i < 8; ++i)
      _msg[SHA256_BLOCK_SIZE - 1 - i] = ((stream_size*8) >> i*8) & 0xff;

    _sha256_calculate(_msg, result);

    return true;
  }

  if(len < SHA256_BLOCK_SIZE){
    uint64_t block_n = ((len < 56) ? 1 : 2);
    uint64_t _msg_len = block_n * SHA256_BLOCK_SIZE;

    //create temp space
    auto _msg = new uint8_t[_msg_len]{0};

    //copy memory
    memcpy(_msg, msg, len);

    //add needed message
    _msg[len] = 0x80;

    //set original message length
    for(int i = 0; i < 8; ++i)
      _msg[block_n * SHA256_BLOCK_SIZE - 1 - i] = ((stream_size*8) >> i*8) & 0xff;

    auto _mp = _msg;
    for (int i = 0; i < block_n; ++i){
      //calculate this block
      _sha256_calculate(_mp, result);
      //_mp point to the next block
      _mp += SHA256_BLOCK_SIZE;
    }
    _mp = nullptr;

    delete [] _msg;
    _msg = nullptr;

    return true;
  }

  return false;
}

uint8_t *sha::sha256_stream::get_8_result() {
  auto result_8 = new uint8_t[32];

  for (int i = 0; i < 8; ++i){
    result_8[i*4 + 3] = this->result[i];
    result_8[i*4 + 2] = this->result[i] >> 8;
    result_8[i*4 + 1] = this->result[i] >> 16;
    result_8[i*4] = this->result[i] >> 24;
  }

  return result_8;
}