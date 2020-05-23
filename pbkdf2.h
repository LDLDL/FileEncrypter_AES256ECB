//
// Created by yuki on 2020/5/16.
//

#ifndef FILEENCRYPTER__PBKDF2_H_
#define FILEENCRYPTER__PBKDF2_H_

#include "sha256.h"

/// \file pbkdf2.h
/// \brief header file for pbkdf2
///        all things are in the pbkdf2 namespace

namespace pbkdf2{

//salt
static const uint8_t init_salt[32]{
    0x59, 0x55, 0x4b, 0x49, //YUKI
    0x79, 0x75, 0x6b, 0x69, //yuki
    0x4c, 0x44, 0x4c, 0x44, 0x4c, //LDLDL
    0x6c, 0x64, 0x6c, 0x64, 0x6c, //ldldl
    0x4d, 0x55, 0x47, 0x49, 0x59, 0x55, //MUGIYU
    0x6d, 0x75, 0x67, 0x69, 0x79, 0x75, //mugiyu
    0x00, 0x00
};

/// \brief pbkdf2: password based key derivation function 2
/// \details hmac function is sha256, key length is 256.
/// \param pwd password string
/// \param iter iteration times
/// \return return a pointer to result uint8_t array
///         length of the array is 32.
uint8_t *pbkdf2_8_32_sha256(std::string &pwd, uint64_t iter);

/// \brief pbkdf2: password based key derivation function 2
/// \details hmac function is sha256, key length is 256.
/// \param pwd password string
/// \param iter iteration times
/// \return return a pointer to result uin32_t array
///         length of the array is 8.
uint32_t *pbkdf2_32_8_sha256(std::string &pwd, uint64_t iter);

}

#endif //FILEENCRYPTER__PBKDF2_H_
