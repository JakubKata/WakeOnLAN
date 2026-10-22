#pragma once
#include <cstdint>
#include "esp_err.h"

namespace device_clock {
// Only called over an authenticated provisioning session.
esp_err_t set_from_phone(int64_t unix_seconds, bool physical_recovery);
// Requires connected Wi-Fi; fails closed until a fresh clock is available.
bool synchronize();
// Advance the persistent lower bound only after a verified cloud TLS session.
void checkpoint();
}  // namespace device_clock
