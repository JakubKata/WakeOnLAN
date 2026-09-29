#pragma once

#include <string>

#include "esp_err.h"

// Device identity issued by the server on DEVICE_CLAIM, kept in NVS namespace "wol".
struct Credentials {
  std::string device_id;
  std::string secret;
};

namespace credentials {

bool load(Credentials& out);
esp_err_t save(const Credentials& creds);
esp_err_t save_secret(const std::string& secret);
// Forgets the identity only; the claim token records below survive.
esp_err_t erase();

// A claim token entered on the console; it takes precedence over CONFIG_WOL_CLAIM_TOKEN.
bool load_claim_token(std::string& out);
esp_err_t save_claim_token(const std::string& token);

// The last claim token the server consumed or rejected, so it is never sent again.
bool is_claim_token_used(const std::string& token);
esp_err_t mark_claim_token_used(const std::string& token);

}  // namespace credentials
