#include "credentials.hpp"

#include <array>
#include <cstring>
#include <mutex>

#include "esp_random.h"
#include "mbedtls/base64.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"
#include "nvs.h"

namespace {
constexpr const char* NAMESPACE = "wol";
constexpr const char* KEY = "identity";
std::mutex mutex;

struct Record {
  uint8_t version;
  uint8_t paired;
  char id[129];
  char secret[129];
  char claim[129];
};

class Handle {
 public:
  Handle() : error(nvs_open(NAMESPACE, NVS_READWRITE, &value)) {}
  ~Handle() { if (error == ESP_OK) nvs_close(value); }
  nvs_handle_t value = 0;
  esp_err_t error;
};

bool terminated(const char* value, size_t size) { return std::memchr(value, '\0', size) != nullptr; }

esp_err_t read(Handle& nvs, Record& record) {
  if (nvs.error != ESP_OK) return nvs.error;
  size_t size = sizeof(record);
  const esp_err_t err = nvs_get_blob(nvs.value, KEY, &record, &size);
  if (err != ESP_OK) return err;
  if (size != sizeof(record) || record.version != 1 || record.paired > 1 ||
      !terminated(record.id, sizeof(record.id)) || !record.id[0] ||
      !terminated(record.secret, sizeof(record.secret)) || !record.secret[0] ||
      !terminated(record.claim, sizeof(record.claim))) return ESP_ERR_INVALID_STATE;
  return ESP_OK;
}

esp_err_t write(Handle& nvs, const Record& record) {
  if (nvs.error != ESP_OK) return nvs.error;
  esp_err_t err = nvs_set_blob(nvs.value, KEY, &record, sizeof(record));
  if (err == ESP_OK) err = nvs_commit(nvs.value);
  return err;
}

void encode(const uint8_t* bytes, size_t length, char* output) {
  size_t written = 0;
  mbedtls_base64_encode(reinterpret_cast<unsigned char*>(output), 129, &written, bytes, length);
  for (size_t i = 0; i < written; ++i) {
    if (output[i] == '+') output[i] = '-';
    if (output[i] == '/') output[i] = '_';
    if (output[i] == '=') { output[i] = '\0'; break; }
  }
}

esp_err_t update(bool paired, bool change_paired, const std::string& claim,
                 const std::string* expected_claim = nullptr) {
  std::lock_guard<std::mutex> lock(mutex);
  Handle nvs;
  Record record{};
  esp_err_t err = read(nvs, record);
  if (err != ESP_OK) return err;
  if (claim.size() >= sizeof(record.claim)) return ESP_ERR_INVALID_ARG;
  // A BLE retry may replace the claim while an older cloud request is in flight.
  const std::string next_claim = expected_claim && *expected_claim != record.claim ? record.claim : claim;
  if (record.paired == (change_paired ? paired : record.paired) && next_claim == record.claim) {
    mbedtls_platform_zeroize(&record, sizeof(record));
    return ESP_OK;
  }
  if (change_paired) record.paired = paired;
  std::memset(record.claim, 0, sizeof(record.claim));
  std::memcpy(record.claim, next_claim.data(), next_claim.size());
  err = write(nvs, record);
  mbedtls_platform_zeroize(&record, sizeof(record));
  return err;
}
}  // namespace

namespace credentials {
bool load(Credentials& out) {
  std::lock_guard<std::mutex> lock(mutex);
  Handle nvs;
  Record record{};
  if (read(nvs, record) != ESP_OK) return false;
  out = Credentials{record.id, record.secret, record.claim, record.paired == 1};
  mbedtls_platform_zeroize(&record, sizeof(record));
  return true;
}

esp_err_t ensure_identity() {
  std::lock_guard<std::mutex> lock(mutex);
  Handle nvs;
  Record record{};
  esp_err_t err = read(nvs, record);
  if (err == ESP_OK) { mbedtls_platform_zeroize(&record, sizeof(record)); return ESP_OK; }
  if (err != ESP_ERR_NVS_NOT_FOUND) return err;

  record.version = 1;
  // Preserve existing installations during migration to the atomic format.
  size_t id_size = sizeof(record.id), secret_size = sizeof(record.secret);
  const esp_err_t id_err = nvs_get_str(nvs.value, "device_id", record.id, &id_size);
  const esp_err_t secret_err = nvs_get_str(nvs.value, "secret", record.secret, &secret_size);
  if (id_err == ESP_OK && secret_err == ESP_OK) {
    record.paired = 1;
  } else if (id_err == ESP_ERR_NVS_NOT_FOUND && secret_err == ESP_ERR_NVS_NOT_FOUND) {
    std::array<uint8_t, 32> secret{}, digest{};
    esp_fill_random(secret.data(), secret.size());
    if (mbedtls_sha256(secret.data(), secret.size(), digest.data(), 0) != 0) return ESP_FAIL;
    encode(secret.data(), secret.size(), record.secret);
    encode(digest.data(), digest.size(), record.id);
    mbedtls_platform_zeroize(secret.data(), secret.size());
  } else {
    return ESP_ERR_INVALID_STATE;
  }
  err = write(nvs, record);
  mbedtls_platform_zeroize(&record, sizeof(record));
  if (err == ESP_OK) {
    // Cleanup after commit; interrupted cleanup cannot lose the identity.
    nvs_erase_key(nvs.value, "device_id");
    nvs_erase_key(nvs.value, "secret");
    nvs_erase_key(nvs.value, "claim");
    nvs_erase_key(nvs.value, "used_claim");
    err = nvs_commit(nvs.value);
  }
  return err;
}

esp_err_t save_claim_token(const std::string& token) { return update(false, false, token); }
esp_err_t mark_paired(const std::string& expected_claim) { return update(true, true, "", &expected_claim); }
esp_err_t mark_unpaired() { return update(false, true, ""); }
esp_err_t clear_claim_token(const std::string& expected_claim) { return update(false, false, "", &expected_claim); }
}  // namespace credentials
