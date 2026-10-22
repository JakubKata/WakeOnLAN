#pragma once

#include <string_view>

namespace onboarding {
// Custom requests are flat JSON objects. Bound parser depth before calling cJSON,
// including for inputs supplied by an authenticated but malfunctioning client.
inline bool bounded_request(std::string_view input) {
  if (input.empty() || input.size() > 512) return false;
  bool quoted = false, escaped = false;
  unsigned depth = 0;
  for (size_t i = 0; i < input.size(); ++i) {
    const char c = input[i];
    if (c == '\0') return false;
    if (quoted) {
      if (escaped) {
        // cJSON stores C strings; reject decoded NUL rather than accepting a prefix.
        if (c == 'u' && input.substr(i + 1, 4) == "0000") return false;
        escaped = false;
      } else if (c == '\\') escaped = true;
      else if (c == '"') quoted = false;
    } else if (c == '"') quoted = true;
    else if (c == '[' || c == ']') return false;
    else if (c == '{') { if (++depth > 1) return false; }
    else if (c == '}') { if (depth == 0) return false; --depth; }
  }
  return !quoted && depth == 0;
}
}  // namespace onboarding
