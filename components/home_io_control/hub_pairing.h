#pragma once

/// @file hub_pairing.h
/// @brief Internal pairing-state model for hub-owned discovery and key-exchange flows.

#include "proto_frame.h"
#include "radio_interface.h"
#include <cstdint>
#include <string>

namespace esphome {
namespace home_io_control {

namespace pairing {

enum class PairingState : uint8_t {
  IDLE,
  TX_DISCOVER,
  WAIT_DISCOVER_RESPONSE,
  TX_KEY_INIT,
  WAIT_KEY_CHALLENGE,
  TX_KEY_TRANSFER,
  WAIT_KEY_CONFIRM,
  PERSIST_DEVICE,
  COMPLETE,
  FAILED,
};

struct PairingContext {
  PairingState state{PairingState::IDLE};
  IoDevice device{};
  IoFrame req{};
  IoFrame resp{};
  IoFrame rx{};
  IoFrame key_init{};
  RadioRxPacket packet{};
  std::string device_id;
};

}  // namespace pairing

}  // namespace home_io_control
}  // namespace esphome