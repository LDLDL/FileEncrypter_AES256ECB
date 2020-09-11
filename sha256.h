//
// Created by yuki on 2020/5/16.
//

#ifndef FILEENCRYPTER__SHA256_H_
#define FILEENCRYPTER__SHA256_H_

#include <cstring>
#include <string>
#include <bit>

/// \file sha.h
/// \brief header file for sha256
///        all things are in the sha namespace

namespace sha{

//hash initial values
static const uint32_t hinit[8] = {
    0x6a09e667, //h0
    0xbb67ae85, //h1
    0x3c6ef372, //h2
    0xa54ff53a, //h3
    0x510e527f, //h4
    0x9b05688c, //h5
    0x1f83d9ab, //h6
    0x5be0cd19  //h7
};

//hash constant values
static const uint32_t hconst[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

//the size of one block of sha256 is 512bits, 64bytes.
static const uint8_t SHA256_BLOCK_SIZE = 64;

/// \brief ma function for sha256 calculating
static inline uint32_t _ma(uint32_t x, uint32_t y, uint32_t z);

/// \brief ch function for sha256 calculating
static inline uint32_t _ch(uint32_t x, uint32_t y, uint32_t z);

/// \brief big sigma0 function for sha256 calculating
static inline uint32_t _bsig0(uint32_t x);

/// \brief big sigma1 function for sha256 calculating
static inline uint32_t _bsig1(uint32_t x);

/// \brief small sigma0 function for sha256 calculating
static inline uint32_t _ssig0(uint32_t x);

/// \brief small sigma1 function for sha256 calculating
static inline uint32_t _ssig1(uint32_t x);

/// \brief calculate a block of message
/// \param msg a pointer to the first element of message block
/// \param result a pointer to the result array
static inline void _sha256_calculate(const uint8_t *msg, uint32_t *result);

/// \brief calculate sha256
/// \param msg message string
/// \return return a pointer to sha256 value array
///         the length of the array is 8, type is uint32_t
uint32_t *sha256(std::string &msg);

/// \brief calculate sha256
/// \param msg a pointer to message array
/// \param len the length of the message
/// \return return a pointer to sha256 value array
///         the length of the array is 8, type is uint32_t
uint32_t *sha256(uint8_t *msg, uint64_t len);

/// \brief calculate sha256
/// \param msg a pointer to message array
/// \param len the length of the message
/// \return return a pointer to sga256 value array
///         the length of the array is 32, type is uin8_t
uint8_t *sha256_8(uint8_t *msg, uint64_t len);

/// \brief calculate sha256
/// \param msg message string
/// \return return a pointer to sga256 value array
///         the length of the array is 32, type is uin8_t
uint8_t *sha256_8(std::string &msg);

/// \class sha256_stream
class sha256_stream {
 private:
  uint32_t *result;
  bool finish = false;
 public:
  sha256_stream();

  ~sha256_stream();

  bool stream_add(uint8_t *msg, uint64_t len);

  uint8_t *get_8_result();
};

}

#endif //FILEENCRYPTER__SHA256_H_
