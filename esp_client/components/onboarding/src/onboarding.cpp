#include "onboarding.hpp"
#include "onboarding_request.hpp"

#include <atomic>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <string>

#include "cJSON.h"
#include "credentials.hpp"
#include "device_clock.hpp"
#include "driver/gpio.h"
#include "esp_check.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs.h"
#include "protocomm_security.h"
#include "protocomm_security2.h"
#include "sdkconfig.h"
#include "wifi.hpp"
#include "wifi_provisioning/manager.h"
#include "wifi_provisioning/scheme_ble.h"

namespace {
constexpr const char* TAG = "onboarding";
constexpr unsigned WINDOW_MS = 10 * 60 * 1000;
constexpr unsigned MAX_AUTH_FAILURES = 5;
std::atomic<bool> active{false};
std::atomic<bool> completion_pending{false};
std::atomic<bool> wifi_submitted{false};
std::atomic<bool> enrollment_prepared{false};
std::atomic<bool> wifi_success{false};
std::atomic<bool> cloud_confirmed{false};
bool physical_setup = false;
unsigned auth_failures = 0;
char service_name[30]{};
char salt[16]{};
char verifier[384]{};
wifi_prov_security2_params_t security{};
wifi_config_t previous_wifi{};

bool token_valid(const char* token) {
  if (!token) return false;
  const size_t length = std::strlen(token);
  if (length < 16 || length > 128) return false;
  for (size_t i = 0; i < length; ++i) {
    const char c = token[i];
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
          (c >= '0' && c <= '9') || c == '-' || c == '_')) return false;
  }
  return true;
}

esp_err_t response(cJSON* result, uint8_t** output, ssize_t* output_length) {
  if (!result) return ESP_ERR_NO_MEM;
  char* serialized = cJSON_PrintUnformatted(result);
  cJSON_Delete(result);
  if (!serialized) return ESP_ERR_NO_MEM;
  *output = reinterpret_cast<uint8_t*>(serialized);
  *output_length = std::strlen(serialized);
  return ESP_OK;
}

esp_err_t claim_handler(uint32_t, const uint8_t* input, ssize_t length,
                        uint8_t** output, ssize_t* output_length, void*) {
  // Protocomm authenticates and decrypts before dispatching this endpoint.
  if (!active.load() || length <= 0 || length > 512 || std::memchr(input, 0, length)) return ESP_ERR_INVALID_ARG;
  const std::string text(reinterpret_cast<const char*>(input), length);
  if (!onboarding::bounded_request(text)) return ESP_ERR_INVALID_ARG;
  cJSON* request = cJSON_ParseWithOpts(text.c_str(), nullptr, true);
  if (!request || !cJSON_IsObject(request)) { cJSON_Delete(request); return ESP_ERR_INVALID_ARG; }
  const cJSON* operation = cJSON_GetObjectItemCaseSensitive(request, "op");
  if (!cJSON_IsString(operation)) { cJSON_Delete(request); return ESP_ERR_INVALID_ARG; }
  const std::string op(operation->valuestring);
  bool valid = true;
  unsigned op_count = 0, token_count = 0, time_count = 0;
  for (const cJSON* item = request->child; item; item = item->next) {
    if (!std::strcmp(item->string, "op")) ++op_count;
    else if (!std::strcmp(item->string, "token")) ++token_count;
    else if (!std::strcmp(item->string, "time")) ++time_count;
    else valid = false;
  }
  if (!valid || op_count != 1 || token_count > 1 || time_count > 1) {
    cJSON_Delete(request); return ESP_ERR_INVALID_ARG;
  }
  Credentials identity;
  if (!credentials::load(identity)) { cJSON_Delete(request); return ESP_FAIL; }
  cJSON* result = nullptr;
  if (op == "info" && token_count == 0 && time_count == 0) {
    result = cJSON_CreateObject();
    if (!result || !cJSON_AddStringToObject(result, "device_id", identity.device_id.c_str()) ||
        !cJSON_AddBoolToObject(result, "paired", identity.paired)) {
      cJSON_Delete(request); cJSON_Delete(result); return ESP_ERR_NO_MEM;
    }
  } else if (op == "claim" || op == "configure") {
    const cJSON* timestamp = cJSON_GetObjectItemCaseSensitive(request, "time");
    const cJSON* token = cJSON_GetObjectItemCaseSensitive(request, "token");
    const bool pairing = op == "claim";
    valid = cJSON_IsNumber(timestamp) && std::isfinite(timestamp->valuedouble) &&
            std::floor(timestamp->valuedouble) == timestamp->valuedouble &&
            timestamp->valuedouble >= 1767225600 && timestamp->valuedouble < 4102444800.0;
    if (pairing) valid = valid && cJSON_IsString(token) && token_valid(token->valuestring) &&
                          (!identity.paired || physical_setup);
    else valid = valid && token_count == 0 && identity.paired && physical_setup;
    if (!valid) { cJSON_Delete(request); return ESP_ERR_INVALID_ARG; }
    esp_err_t err = device_clock::set_from_phone(static_cast<int64_t>(timestamp->valuedouble), physical_setup);
    if (err == ESP_OK && pairing) err = credentials::save_claim_token(token->valuestring);
    if (err != ESP_OK) { cJSON_Delete(request); return err; }
    enrollment_prepared.store(true);
    result = cJSON_CreateObject();
    if (!result || !cJSON_AddBoolToObject(result, "ok", true)) {
      cJSON_Delete(request); cJSON_Delete(result); return ESP_ERR_NO_MEM;
    }
  } else {
    cJSON_Delete(request); return ESP_ERR_INVALID_ARG;
  }
  cJSON_Delete(request);
  return response(result, output, output_length);
}

void on_event(void*, esp_event_base_t base, int32_t id, void*) {
  if (base == PROTOCOMM_SECURITY_SESSION_EVENT &&
      (id == PROTOCOMM_SECURITY_SESSION_CREDENTIALS_MISMATCH ||
       id == PROTOCOMM_SECURITY_SESSION_INVALID_SECURITY_PARAMS)) {
    if (++auth_failures >= MAX_AUTH_FAILURES && active.load()) wifi_prov_mgr_stop_provisioning();
  } else if (base == WIFI_PROV_EVENT && id == WIFI_PROV_CRED_RECV) {
    wifi_success.store(false);
    cloud_confirmed.store(false);
    wifi_submitted.store(true);
  } else if (base == WIFI_PROV_EVENT && id == WIFI_PROV_CRED_SUCCESS) {
    wifi_success.store(true);
    if (cloud_confirmed.load()) onboarding::complete();
  } else if (base == WIFI_PROV_EVENT && id == WIFI_PROV_CRED_FAIL) {
    wifi_success.store(false);
    // Permit correction of a mistyped Wi-Fi password within this bounded session.
    wifi_prov_mgr_reset_sm_state_on_failure();
  } else if (base == WIFI_PROV_EVENT && id == WIFI_PROV_END) {
    active.store(false);
    wifi_prov_mgr_deinit();
    if (!wifi_success.load() && previous_wifi.sta.ssid[0]) {
      // A cancelled or failed reconfiguration must preserve the previous network.
      esp_wifi_set_storage(WIFI_STORAGE_FLASH);
      esp_wifi_set_config(WIFI_IF_STA, &previous_wifi);
    }
    std::memset(&previous_wifi, 0, sizeof(previous_wifi));
    wifi::set_provisioning(false);
  }
}

void close_after_success(void*) {
  vTaskDelay(pdMS_TO_TICKS(10000));
  if (active.load()) wifi_prov_mgr_stop_provisioning();
  vTaskDelete(nullptr);
}

void expire_window(void*) {
  vTaskDelay(pdMS_TO_TICKS(WINDOW_MS));
  if (active.load()) wifi_prov_mgr_stop_provisioning();
  vTaskDelete(nullptr);
}

bool button_held() {
  const auto pin = static_cast<gpio_num_t>(CONFIG_WOL_SETUP_GPIO);
  gpio_config_t config{};
  config.pin_bit_mask = 1ULL << CONFIG_WOL_SETUP_GPIO;
  config.mode = GPIO_MODE_INPUT;
  config.pull_up_en = GPIO_PULLUP_ENABLE;
  if (gpio_config(&config) != ESP_OK || gpio_get_level(pin) != 0) return false;
  for (int tick = 0; tick < 30; ++tick) {
    vTaskDelay(pdMS_TO_TICKS(100));
    if (gpio_get_level(pin) != 0) return false;
  }
  return true;
}

esp_err_t load_factory() {
  nvs_handle_t handle;
  ESP_RETURN_ON_ERROR(nvs_open("factory", NVS_READONLY, &handle), TAG, "factory provisioning data missing");
  size_t name_length = sizeof(service_name), salt_length = sizeof(salt), verifier_length = sizeof(verifier);
  esp_err_t err = nvs_get_str(handle, "name", service_name, &name_length);
  if (err == ESP_OK) err = nvs_get_blob(handle, "salt", salt, &salt_length);
  if (err == ESP_OK) err = nvs_get_blob(handle, "verifier", verifier, &verifier_length);
  nvs_close(handle);
  if (err != ESP_OK) return err;
  if (std::strncmp(service_name, "WOL_", 4) || name_length < 11 || salt_length != sizeof(salt) ||
      verifier_length != sizeof(verifier)) return ESP_ERR_INVALID_STATE;
  security.salt = salt;
  security.salt_len = salt_length;
  security.verifier = verifier;
  security.verifier_len = verifier_length;
  return ESP_OK;
}
}  // namespace

namespace onboarding {
esp_err_t start() {
  physical_setup = button_held();
  Credentials identity;
  if (!credentials::load(identity)) return ESP_ERR_INVALID_STATE;
  if (identity.paired && !physical_setup) return ESP_OK;
  ESP_RETURN_ON_ERROR(load_factory(), TAG, "invalid factory data");
  // Pin the nonce-counter security patch as well as the scheme; no legacy fallback.
  if (protocomm_security2.patch_ver != 1) return ESP_ERR_NOT_SUPPORTED;
  ESP_RETURN_ON_ERROR(esp_event_handler_register(WIFI_PROV_EVENT, ESP_EVENT_ANY_ID, on_event, nullptr), TAG, "provisioning events");
  ESP_RETURN_ON_ERROR(esp_event_handler_register(PROTOCOMM_SECURITY_SESSION_EVENT, ESP_EVENT_ANY_ID, on_event, nullptr), TAG, "security events");
  wifi_prov_mgr_config_t config{};
  config.scheme = wifi_prov_scheme_ble;
  config.scheme_event_handler = WIFI_PROV_SCHEME_BLE_EVENT_HANDLER_FREE_BTDM;
  ESP_RETURN_ON_ERROR(wifi_prov_mgr_init(config), TAG, "provisioning manager");
  // UUID 021a9004-0382-4aea-bff4-6b3f1c5adfb4, in BLE little-endian form.
  uint8_t uuid[] = {0xb4,0xdf,0x5a,0x1c,0x3f,0x6b,0xf4,0xbf,0xea,0x4a,0x82,0x03,0x04,0x90,0x1a,0x02};
  ESP_RETURN_ON_ERROR(wifi_prov_scheme_ble_set_service_uuid(uuid), TAG, "BLE service");
  ESP_RETURN_ON_ERROR(wifi_prov_mgr_endpoint_create("wol-claim"), TAG, "claim endpoint");
  ESP_RETURN_ON_ERROR(wifi_prov_mgr_disable_auto_stop(1000), TAG, "provisioning lifetime");
  ESP_RETURN_ON_ERROR(esp_wifi_get_config(WIFI_IF_STA, &previous_wifi), TAG, "previous network");
  wifi::set_provisioning(true);
  ESP_RETURN_ON_ERROR(wifi_prov_mgr_start_provisioning(WIFI_PROV_SECURITY_2, &security, service_name, nullptr), TAG, "start BLE");
  active.store(true);
  ESP_RETURN_ON_ERROR(wifi_prov_mgr_endpoint_register("wol-claim", claim_handler, nullptr), TAG, "claim handler");
  if (xTaskCreate(expire_window, "setup_timeout", 2048, nullptr, 4, nullptr) != pdPASS) {
    wifi_prov_mgr_stop_provisioning();
    return ESP_ERR_NO_MEM;
  }
  ESP_LOGI(TAG, "secure setup window open for 10 minutes");
  return ESP_OK;
}
void complete() {
  if (!active.load() || !wifi_submitted.load() || !enrollment_prepared.load()) return;
  cloud_confirmed.store(true);
  if (wifi_success.load() && !completion_pending.exchange(true)) {
    if (xTaskCreate(close_after_success, "setup_complete", 2048, nullptr, 4, nullptr) != pdPASS) {
      wifi_prov_mgr_stop_provisioning();
    }
  }
}
bool in_progress() { return active.load(); }
}  // namespace onboarding
