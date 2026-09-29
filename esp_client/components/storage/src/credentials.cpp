#include "credentials.hpp"

#include <utility>

#include "esp_log.h"
#include "nvs.h"

namespace {

constexpr const char* TAG = "credentials";
constexpr const char* NAMESPACE = "wol";
constexpr const char* KEY_DEVICE_ID = "device_id";
constexpr const char* KEY_SECRET = "secret";
constexpr const char* KEY_CLAIM = "claim";
constexpr const char* KEY_USED_CLAIM = "used_claim";

class NvsHandle {
public:
  explicit NvsHandle(nvs_open_mode_t mode) : err_(nvs_open(NAMESPACE, mode, &handle_)) {}
  ~NvsHandle() {
    if (err_ == ESP_OK) nvs_close(handle_);
  }
  NvsHandle(const NvsHandle&) = delete;
  NvsHandle& operator=(const NvsHandle&) = delete;

  esp_err_t error() const { return err_; }
  nvs_handle_t get() const { return handle_; }

private:
  nvs_handle_t handle_ = 0;
  esp_err_t err_;
};

bool read_string(nvs_handle_t handle, const char* key, std::string& out) {
  size_t length = 0;
  if (nvs_get_str(handle, key, nullptr, &length) != ESP_OK || length <= 1) return false;
  std::string value(length, '\0');
  if (nvs_get_str(handle, key, value.data(), &length) != ESP_OK) return false;
  value.resize(length - 1);
  out = std::move(value);
  return true;
}

bool read_key(const char* key, std::string& out) {
  NvsHandle nvs(NVS_READONLY);
  return nvs.error() == ESP_OK && read_string(nvs.get(), key, out);
}

esp_err_t erase_key(nvs_handle_t handle, const char* key) {
  const esp_err_t err = nvs_erase_key(handle, key);
  return err == ESP_ERR_NVS_NOT_FOUND ? ESP_OK : err;
}

esp_err_t write(const char* device_id, const std::string& secret) {
  NvsHandle nvs(NVS_READWRITE);
  esp_err_t err = nvs.error();
  if (err == ESP_OK && device_id != nullptr) err = nvs_set_str(nvs.get(), KEY_DEVICE_ID, device_id);
  if (err == ESP_OK) err = nvs_set_str(nvs.get(), KEY_SECRET, secret.c_str());
  if (err == ESP_OK) err = nvs_commit(nvs.get());
  if (err != ESP_OK) ESP_LOGE(TAG, "saving credentials failed: %s", esp_err_to_name(err));
  return err;
}

}  // namespace

namespace credentials {

bool load(Credentials& out) {
  NvsHandle nvs(NVS_READONLY);
  if (nvs.error() != ESP_OK) return false;
  Credentials creds;
  if (!read_string(nvs.get(), KEY_DEVICE_ID, creds.device_id) || !read_string(nvs.get(), KEY_SECRET, creds.secret)) {
    return false;
  }
  out = std::move(creds);
  return true;
}

esp_err_t save(const Credentials& creds) {
  return write(creds.device_id.c_str(), creds.secret);
}

esp_err_t save_secret(const std::string& secret) {
  return write(nullptr, secret);
}

esp_err_t erase() {
  NvsHandle nvs(NVS_READWRITE);
  esp_err_t err = nvs.error();
  if (err == ESP_OK) err = erase_key(nvs.get(), KEY_DEVICE_ID);
  if (err == ESP_OK) err = erase_key(nvs.get(), KEY_SECRET);
  if (err == ESP_OK) err = nvs_commit(nvs.get());
  if (err != ESP_OK) ESP_LOGE(TAG, "erasing credentials failed: %s", esp_err_to_name(err));
  return err;
}

bool load_claim_token(std::string& out) {
  return read_key(KEY_CLAIM, out);
}

esp_err_t save_claim_token(const std::string& token) {
  NvsHandle nvs(NVS_READWRITE);
  esp_err_t err = nvs.error();
  if (err == ESP_OK) err = nvs_set_str(nvs.get(), KEY_CLAIM, token.c_str());
  if (err == ESP_OK) err = nvs_commit(nvs.get());
  if (err != ESP_OK) ESP_LOGE(TAG, "saving claim token failed: %s", esp_err_to_name(err));
  return err;
}

bool is_claim_token_used(const std::string& token) {
  std::string used;
  return read_key(KEY_USED_CLAIM, used) && used == token;
}

esp_err_t mark_claim_token_used(const std::string& token) {
  NvsHandle nvs(NVS_READWRITE);
  esp_err_t err = nvs.error();
  if (err == ESP_OK) err = nvs_set_str(nvs.get(), KEY_USED_CLAIM, token.c_str());
  if (err == ESP_OK) err = erase_key(nvs.get(), KEY_CLAIM);
  if (err == ESP_OK) err = nvs_commit(nvs.get());
  if (err != ESP_OK) ESP_LOGE(TAG, "recording used claim token failed: %s", esp_err_to_name(err));
  return err;
}

}  // namespace credentials
