#pragma once

/// @file hub_exchange.h
/// @brief Internal exchange-state model for hub-owned authenticated non-pairing flows.

#include "proto_frame.h"
#include "radio_interface.h"
#include <cstdint>
#include <string>

namespace esphome {
namespace home_io_control {

namespace exchange {

enum class OutboundExchangeState : uint8_t {
  IDLE,
  TX_REQUEST,
  WAIT_FIRST_RESPONSE,
  BUILD_AUTH_RESPONSE,
  TX_AUTH_RESPONSE,
  WAIT_FINAL_RESPONSE,
  SUCCESS,
  FAILED,
};

enum class InboundAuthState : uint8_t {
  IDLE,
  TX_CHALLENGE,
  WAIT_CHALLENGE_RESPONSE,
  VERIFIED,
  FAILED,
};

struct OutboundExchangeContext {
  OutboundExchangeState state{OutboundExchangeState::IDLE};
  uint8_t try_index{0};
  bool saw_challenge{false};
  uint32_t exchange_start_ms{0};
  uint32_t wait_ms{0};
  uint32_t first_response_ms{0};
  IoFrame rx{};
};

struct InboundAuthContext {
  InboundAuthState state{InboundAuthState::IDLE};
  IoFrame challenge{};
};

}  // namespace exchange

}  // namespace home_io_control
}  // namespace esphome