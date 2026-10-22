#pragma once

#include <string>
#include "esp_err.h"

// Persisted as one atomic encrypted-NVS record before the first cloud request.
struct Credentials {
  std::string device_id;
  std::string secret;
  std::string claim_token;
  bool paired = false;
};

namespace credentials {
bool load(Credentials& out);
// Requires an active hardware entropy source. Never replaces damaged credentials.
esp_err_t ensure_identity();
esp_err_t save_claim_token(const std::string& token);
esp_err_t mark_paired(const std::string& expected_claim);
// Clear the old pairing, but preserve a claim replaced by BLE since this session began.
esp_err_t mark_unpaired(const std::string& expected_claim);
esp_err_t clear_claim_token(const std::string& expected_claim);
}  // namespace credentials
