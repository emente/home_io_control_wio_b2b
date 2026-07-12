/// @file corpus_crypto_test.cpp
/// @brief Recorded crypto ground truth from `key: corpus` golden-frame captures.
///
/// Runs over every capture whose `key` promise is `corpus` and whose exchange kind is 
/// `authenticated_command`: rebuilds the HMAC transcript exactly as `create_challenge_resp()`
/// does (proto_commands.cpp) and asserts the recomputed HMAC, under the public corpus key
/// (test_helpers.h :: TEST_SYSTEM_KEY), matches the captured `0x3D` bytes byte-for-byte.
/// This pins IV construction, checksum-byte derivation, and truncation against a real
/// exchange shape instead of only synthetic vectors (tests/proto_crypto_test.cpp already
/// covers the synthetic case).
///
/// Captures that do not match the expected shape cause a loud failure (a corpus bug), not a
/// silent pass; captures with no matching content (e.g. no `0x32` key-transfer frame yet) are
/// skipped with a counted GTEST_SKIP(), never a vacuous pass.

#include "corpus_generated.h"
#include "proto_commands.h"
#include "proto_constants.h"
#include "proto_crypto.h"
#include "proto_frame.h"

#include "corpus_test_helpers.h"
#include "test_helpers.h"

#include <gtest/gtest.h>

#include <cstring>
#include <string>
#include <vector>

using namespace esphome::home_io_control;

namespace {

/// Captures that promise `key: corpus` and describe an authenticated command exchange —
/// the only shape corpus_crypto_test.cpp knows how to replay today (design §6.2).
std::vector<const corpus::CorpusCapture *> authenticated_corpus_captures() {
  return corpus_test::captures_where([](const corpus::CorpusCapture *cap) {
    return cap->key == corpus::KeyMode::CORPUS && cap->has_exchange &&
           cap->kind == corpus::ExchangeKind::AUTHENTICATED_COMMAND;
  });
}

}  // namespace

class CorpusCryptoReplay : public ::testing::TestWithParam<const corpus::CorpusCapture *> {};

TEST_P(CorpusCryptoReplay, AuthenticatedCommandHmacMatchesCapture) {
  const corpus::CorpusCapture *capture = GetParam();
  SCOPED_TRACE(::testing::Message() << "capture=" << capture->id);

  // Locate the origin (first tx frame — a required schema field, not an expectation), then the
  // 0x3C challenge and 0x3D response by their *parsed* cmd byte rather than expect.cmd: cmd
  // expectations are optional per the corpus schema, so a valid capture that omits them must
  // still be locatable here.
  const corpus::CorpusFrame *origin_cf = nullptr;
  const corpus::CorpusFrame *challenge_cf = nullptr;
  const corpus::CorpusFrame *response_cf = nullptr;
  for (uint8_t i = 0; i < capture->frame_count; i++) {
    const corpus::CorpusFrame &cf = capture->frames[i];
    if (origin_cf == nullptr && cf.tx) {
      origin_cf = &cf;
      continue;
    }
    const IoFrame parsed = corpus_test::parse_capture_frame(cf);
    if (challenge_cf == nullptr && !cf.tx && parsed.cmd == CMD_CHALLENGE_REQ) {
      challenge_cf = &cf;
    } else if (response_cf == nullptr && cf.tx && parsed.cmd == CMD_CHALLENGE_RESP) {
      response_cf = &cf;
    }
  }
  ASSERT_NE(origin_cf, nullptr) << "authenticated_command capture must have an origin tx frame";
  ASSERT_NE(challenge_cf, nullptr) << "authenticated_command capture must have a 0x3C challenge frame";
  ASSERT_NE(response_cf, nullptr) << "authenticated_command capture must have a 0x3D response frame";

  IoFrame origin = corpus_test::parse_capture_frame(*origin_cf);
  IoFrame challenge = corpus_test::parse_capture_frame(*challenge_cf);
  IoFrame response = corpus_test::parse_capture_frame(*response_cf);
  ASSERT_EQ(challenge.data_len, HMAC_SIZE) << "0x3C challenge payload must be exactly HMAC_SIZE bytes";
  ASSERT_EQ(response.data_len, HMAC_SIZE) << "0x3D response payload must be exactly HMAC_SIZE bytes";

  // Rebuild the transcript exactly as create_challenge_resp() does (proto_commands.cpp):
  // [origin.cmd, origin.data...], authenticated against the captured challenge.
  uint8_t transcript[FRAME_MAX_SIZE] = {0};
  transcript[0] = origin.cmd;
  std::memcpy(transcript + 1, origin.data, origin.data_len);
  const uint8_t transcript_len = static_cast<uint8_t>(origin.data_len + 1);

  uint8_t computed_hmac[HMAC_SIZE] = {0};
  ASSERT_TRUE(crypto::create_hmac(transcript, transcript_len, challenge.data, test::TEST_SYSTEM_KEY, computed_hmac));
  EXPECT_EQ(std::memcmp(computed_hmac, response.data, HMAC_SIZE), 0)
      << "recomputed HMAC does not match captured 0x3D bytes under the corpus key";

  const bool hmac_actually_valid =
      crypto::verify_hmac(transcript, transcript_len, response.data, challenge.data, test::TEST_SYSTEM_KEY);
  if (response_cf->has_hmac_valid) {
    // `hmac_valid` is a per-frame expectation (validate.py, build.py); wiring it here gives
    // `hmac_valid: false` a real meaning for a future deliberately-tampered fixture instead of
    // being an accepted-but-never-checked field.
    EXPECT_EQ(hmac_actually_valid, response_cf->hmac_valid)
        << "verify_hmac result does not match the capture's hmac_valid expectation";
  } else {
    EXPECT_TRUE(hmac_actually_valid) << "verify_hmac must accept the captured HMAC";
  }

  uint8_t tampered[HMAC_SIZE];
  std::memcpy(tampered, response.data, HMAC_SIZE);
  tampered[0] ^= 0x01;
  EXPECT_FALSE(crypto::verify_hmac(transcript, transcript_len, tampered, challenge.data, test::TEST_SYSTEM_KEY))
      << "a single bit-flip in the captured HMAC must be rejected";
}

/// Key-transfer (0x32) sub-test — no such `key: corpus` capture exists yet (it first lands
/// with the pairing capture, Step H2). Skips loudly with a count so the assertion is visibly
/// dormant rather than silently absent.
TEST(CorpusCryptoKeyTransfer, KeyTransferDecryptsToCorpusKey) {
  int key_transfer_captures = 0;
  for (size_t i = 0; i < corpus::CAPTURE_COUNT; i++) {
    const corpus::CorpusCapture &cap = corpus::CAPTURES[i];
    if (cap.key != corpus::KeyMode::CORPUS)
      continue;
    for (uint8_t f = 0; f < cap.frame_count; f++) {
      const corpus::CorpusFrame &cf = cap.frames[f];
      if (cf.has_cmd && cf.cmd == CMD_KEY_TRANSFER)
        key_transfer_captures++;
    }
  }
  if (key_transfer_captures == 0) {
    GTEST_SKIP() << "no key:corpus capture with a 0x32 key-transfer frame yet (arrives in Step H2)";
  }
  // Placeholder for when H2 lands: locate the 0x31 key-init + 0x32 key-transfer pair and the
  // challenge that seeded it, then assert crypto::crypt_key(...) recovers TEST_SYSTEM_KEY.
  FAIL() << "key_transfer_captures=" << key_transfer_captures
         << " found but decrypt-to-corpus-key assertion is not yet implemented";
}

INSTANTIATE_TEST_SUITE_P(CorpusCrypto, CorpusCryptoReplay, ::testing::ValuesIn(authenticated_corpus_captures()),
                         corpus_test::capture_name_generator);
