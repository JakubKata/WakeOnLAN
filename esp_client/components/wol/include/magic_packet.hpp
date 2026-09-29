#pragma once

#include <array>
#include <cstdint>
#include <string>

#include "esp_err.h"

namespace wol {

using MacAddress = std::array<uint8_t, 6>;

// Accepts AA:BB:CC:DD:EE:FF, AA-BB-CC-DD-EE-FF, AABB.CCDD.EEFF and AABBCCDDEEFF.
bool parse_mac(const std::string& text, MacAddress& out);

// Broadcasts the magic packet on UDP port 9 of the WiFi station interface.
esp_err_t send_magic_packet(const MacAddress& mac);

}  // namespace wol
