#pragma once

/// @file hub_decisions.h
/// @brief Pure transition helpers for hub-owned exchange and pairing frame decisions.

#include "proto_frame.h"

#include <cstdint>
#include <cstring>

namespace esphome {
namespace home_io_control {
namespace decisions {

enum class ExchangeFirstResponseDisposition : uint8_t {
  IGNORE_UNRELATED,
  COMPLETE_DIRECT,
  REQUIRE_AUTH,
};

enum class ExchangeFinalResponseDisposition : uint8_t {
  IGNORE_UNRELATED,
  ACCEPT,
};

enum class PairingDiscoveryDisposition : uint8_t {
  IGNORE,
  ACCEPT,
};

enum class PairingKeyChallengeDisposition : uint8_t {
  IGNORE,
  ACCEPT,
};

// Keep these helpers pure so the host smoke tests can lock down the controller's branching rules
// without having to fake radio timing, retries, or ESPHome component state.
inline bool frame_matches_nodes(const IoFrame &frame, const uint8_t expected_src[NODE_ID_SIZE],
                                const uint8_t expected_dst[NODE_ID_SIZE]) {
  return std::memcmp(frame.src, expected_src, NODE_ID_SIZE) == 0 &&
         std::memcmp(frame.dst, expected_dst, NODE_ID_SIZE) == 0;
}

inline bool frame_matches_exchange_endpoints(const IoFrame &request, const IoFrame &candidate) {
  return frame_matches_nodes(candidate, request.dst, request.src);
}

inline ExchangeFirstResponseDisposition classify_exchange_first_response(const IoFrame &request,
                                                                         const IoFrame &candidate) {
  if (!frame_matches_exchange_endpoints(request, candidate))
    return ExchangeFirstResponseDisposition::IGNORE_UNRELATED;
  // A matching non-0x3C frame is the entire answer for direct-response exchanges such as plain
  // status reads, so the caller must not force it through the authenticated path.
  if (candidate.cmd == CMD_CHALLENGE_REQ)
    return ExchangeFirstResponseDisposition::REQUIRE_AUTH;
  return ExchangeFirstResponseDisposition::COMPLETE_DIRECT;
}

inline ExchangeFinalResponseDisposition classify_exchange_final_response(const IoFrame &request,
                                                                         const IoFrame &candidate) {
  return frame_matches_exchange_endpoints(request, candidate) ? ExchangeFinalResponseDisposition::ACCEPT
                                                              : ExchangeFinalResponseDisposition::IGNORE_UNRELATED;
}

inline PairingDiscoveryDisposition classify_pairing_discovery_response(const IoFrame &candidate) {
  return candidate.cmd == CMD_DISCOVER_RESP ? PairingDiscoveryDisposition::ACCEPT : PairingDiscoveryDisposition::IGNORE;
}

inline PairingKeyChallengeDisposition classify_pairing_key_challenge(const IoFrame &candidate,
                                                                     const uint8_t device_id[NODE_ID_SIZE],
                                                                     const uint8_t controller_id[NODE_ID_SIZE]) {
  // Pairing reuses the normal 0x3C primitive, but here the challenge is only valid when it comes
  // from the device we just discovered and targets this controller. That keeps foreign traffic from
  // contaminating key exchange on a busy channel.
  return candidate.cmd == CMD_CHALLENGE_REQ && candidate.data_len == HMAC_SIZE &&
                 frame_matches_nodes(candidate, device_id, controller_id)
             ? PairingKeyChallengeDisposition::ACCEPT
             : PairingKeyChallengeDisposition::IGNORE;
}

}  // namespace decisions
}  // namespace home_io_control
}  // namespace esphome