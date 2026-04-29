#pragma once

#include <stdint.h>

static inline uint32_t esp_random(void) {
  static uint32_t state = 0x12345678u;
  state = state * 1664525u + 1013904223u;
  return state;
}