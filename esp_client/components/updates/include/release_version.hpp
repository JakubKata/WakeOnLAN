#pragma once

#include <array>
#include <cstdint>
#include <cstddef>
#include <limits>

namespace updates {
// Numeric major.minor.patch only: no signs, suffixes, whitespace or overflow.
inline bool parse_version(const char* text, std::array<uint32_t, 3>& version) {
  for (size_t component = 0; component < version.size(); ++component) {
    uint32_t number = 0;
    if (*text < '0' || *text > '9') return false;
    do {
      const uint32_t digit = *text++ - '0';
      if (number > (std::numeric_limits<uint32_t>::max() - digit) / 10) return false;
      number = number * 10 + digit;
    } while (*text >= '0' && *text <= '9');
    version[component] = number;
    if (component + 1 < version.size()) {
      if (*text++ != '.') return false;
    } else if (*text != '\0') return false;
  }
  return true;
}

inline bool newer_version(const char* next, const char* current) {
  std::array<uint32_t, 3> candidate{}, installed{};
  return parse_version(next, candidate) && parse_version(current, installed) && candidate > installed;
}
}  // namespace updates
