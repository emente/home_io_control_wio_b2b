#pragma once

/// @file proto_crypto.h
/// @brief Cryptographic helpers for the IO-Homecontrol protocol.

#include "proto_frame.h"

namespace esphome {
namespace home_io_control {
namespace crypto {

void compute_checksum(uint8_t byte, uint8_t &c1, uint8_t &c2);
void construct_iv(const uint8_t *data, uint8_t len, const uint8_t challenge[HMAC_SIZE], uint8_t iv[IV_SIZE]);
bool aes128_encrypt(const uint8_t in[AES_BLOCK_SIZE], const uint8_t key[AES_KEY_SIZE], uint8_t out[AES_BLOCK_SIZE]);
bool aes128_decrypt(const uint8_t in[AES_BLOCK_SIZE], const uint8_t key[AES_KEY_SIZE], uint8_t out[AES_BLOCK_SIZE]);
bool create_hmac(const uint8_t *data, uint8_t len, const uint8_t challenge[HMAC_SIZE], const uint8_t key[AES_KEY_SIZE],
                 uint8_t hmac[HMAC_SIZE]);
bool verify_hmac(const uint8_t *data, uint8_t len, const uint8_t hmac[HMAC_SIZE], const uint8_t challenge[HMAC_SIZE],
                 const uint8_t key[AES_KEY_SIZE]);
bool crypt_key(const uint8_t *data, uint8_t len, const uint8_t challenge[HMAC_SIZE], const uint8_t in[AES_KEY_SIZE],
               uint8_t out[AES_KEY_SIZE]);
void generate_challenge(uint8_t out[HMAC_SIZE]);

}  // namespace crypto
}  // namespace home_io_control
}  // namespace esphome
