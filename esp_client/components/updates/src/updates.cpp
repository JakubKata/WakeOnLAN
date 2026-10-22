#include "updates.hpp"
#include "release_version.hpp"

#include <algorithm>
#include <cstring>
#include <mutex>
#include <string_view>

#include "device_clock.hpp"
#include "esp_app_desc.h"
#include "esp_app_format.h"
#include "esp_crt_bundle.h"
#include "esp_efuse.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "onboarding.hpp"
#include "sdkconfig.h"
#include "wifi.hpp"

namespace {
constexpr const char* TAG = "updates";
bool healthy = false;
bool pending_validation = false;
std::mutex health_mutex;

void boot_deadline(void*) {
  vTaskDelay(pdMS_TO_TICKS(120000));
  {
    std::lock_guard<std::mutex> lock(health_mutex);
    if (!healthy) {
      ESP_LOGE(TAG, "new image did not authenticate; rolling back");
      esp_ota_mark_app_invalid_rollback_and_reboot();
    }
  }
  vTaskDelete(nullptr);
}

#if CONFIG_WOL_ENABLE_OTA
#if !CONFIG_SECURE_BOOT || !CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK
#error "OTA requires Secure Boot and bootloader anti-rollback"
#endif
static_assert(std::string_view(CONFIG_WOL_FIRMWARE_URL).substr(0, 8) == "https://" &&
              std::string_view(CONFIG_WOL_FIRMWARE_URL).size() > 8,
              "Production updates require a fixed HTTPS WOL_FIRMWARE_URL");
bool update_started = false;

class Download {
 public:
  explicit Download(const esp_http_client_config_t& config) : http(esp_http_client_init(&config)) {}
  ~Download() {
    if (writing) esp_ota_abort(ota);
    if (http) { esp_http_client_close(http); esp_http_client_cleanup(http); }
  }
  esp_http_client_handle_t http;
  esp_ota_handle_t ota = 0;
  bool writing = false;
};

void check_update() {
  esp_http_client_config_t config{};
  config.url = CONFIG_WOL_FIRMWARE_URL;
  config.crt_bundle_attach = esp_crt_bundle_attach;
  config.timeout_ms = 15000;
  config.disable_auto_redirect = true;
  Download download(config);
  if (!download.http || esp_http_client_open(download.http, 0) != ESP_OK) return;
  const int64_t length = esp_http_client_fetch_headers(download.http);
  const esp_partition_t* partition = esp_ota_get_next_update_partition(nullptr);
  constexpr size_t DESC_OFFSET = sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t);
  constexpr size_t HEADER_BYTES = DESC_OFFSET + sizeof(esp_app_desc_t);
  // Use the stream API deliberately: reject redirects and chunked/oversized responses.
  // esp_https_ota follows redirects independently of disable_auto_redirect in IDF 5.5.
  if (esp_http_client_get_status_code(download.http) != 200 || !partition ||
      length < static_cast<int64_t>(HEADER_BYTES) || length > partition->size) return;
  uint8_t buffer[1024];
  size_t initial = 0;
  const int64_t deadline = esp_timer_get_time() + 10 * 60 * 1000000LL;
  while (initial < HEADER_BYTES) {
    const int count = esp_http_client_read(download.http, reinterpret_cast<char*>(buffer + initial), HEADER_BYTES - initial);
    if (count <= 0 || esp_timer_get_time() >= deadline) return;
    initial += count;
  }
  esp_app_desc_t next{};
  std::memcpy(&next, buffer + DESC_OFFSET, sizeof(next));
  const esp_app_desc_t* current = esp_app_get_description();
  if (buffer[0] != ESP_IMAGE_HEADER_MAGIC || next.magic_word != ESP_APP_DESC_MAGIC_WORD ||
      std::strncmp(next.project_name, current->project_name, sizeof(next.project_name)) ||
      !std::memchr(next.version, '\0', sizeof(next.version)) ||
      !updates::newer_version(next.version, current->version) ||
      next.secure_version < current->secure_version || !esp_efuse_check_secure_version(next.secure_version)) return;

  const esp_partition_t* failed_partition = esp_ota_get_last_invalid_partition();
  esp_app_desc_t failed{};
  if (failed_partition && esp_ota_get_partition_description(failed_partition, &failed) == ESP_OK &&
      !std::strncmp(next.version, failed.version, sizeof(next.version))) {
    // Do not repeatedly reboot into the same image that already failed health validation.
    return;
  }
  if (esp_ota_begin(partition, length, &download.ota) != ESP_OK) return;
  download.writing = true;
  if (esp_ota_write(download.ota, buffer, initial) != ESP_OK) return;
  int64_t received = initial;
  while (received < length) {
    const int count = esp_http_client_read(download.http, reinterpret_cast<char*>(buffer),
                                          std::min<int64_t>(sizeof(buffer), length - received));
    if (count <= 0 || esp_timer_get_time() >= deadline) return;
    if (esp_ota_write(download.ota, buffer, count) != ESP_OK) return;
    received += count;
    vTaskDelay(pdMS_TO_TICKS(10));
  }
  if (!esp_http_client_is_complete_data_received(download.http)) return;
  // esp_ota_end validates the signed image under Secure Boot before selecting it.
  const esp_err_t result = esp_ota_end(download.ota);
  download.writing = false;  // end releases the OTA handle on both success and failure.
  if (result == ESP_OK && esp_ota_set_boot_partition(partition) == ESP_OK) esp_restart();
}

void update_task(void*) {
  vTaskDelay(pdMS_TO_TICKS(30000 + esp_random() % 300000));
  for (;;) {
    wifi::wait_connected();
    while (onboarding::in_progress()) vTaskDelay(pdMS_TO_TICKS(1000));
    if (device_clock::synchronize()) check_update();
    // Convert seconds, avoiding pdMS_TO_TICKS's 32-bit multiplication overflow.
    vTaskDelay(static_cast<TickType_t>((24 * 60 * 60 + esp_random() % 3600) * configTICK_RATE_HZ));
  }
}

void start_updates() {
  if (!update_started && xTaskCreate(update_task, "ota", 8192, nullptr, 3, nullptr) == pdPASS) update_started = true;
}
#endif
}  // namespace

namespace updates {
void start() {
  std::lock_guard<std::mutex> lock(health_mutex);
  esp_ota_img_states_t state;
  pending_validation = esp_ota_get_state_partition(esp_ota_get_running_partition(), &state) == ESP_OK &&
                       state == ESP_OTA_IMG_PENDING_VERIFY;
  if (pending_validation) {
    if (xTaskCreate(boot_deadline, "ota_validation", 3072, nullptr, 4, nullptr) != pdPASS) {
      esp_ota_mark_app_invalid_rollback_and_reboot();
    }
  } else {
    // A stable image may repair its CA bundle even while relay TLS cannot connect.
    healthy = true;
#if CONFIG_WOL_ENABLE_OTA
    start_updates();
#endif
  }
}

void cloud_ready() {
  std::lock_guard<std::mutex> lock(health_mutex);
  if (!healthy) {
    if (pending_validation && esp_ota_mark_app_valid_cancel_rollback() != ESP_OK) return;
    healthy = true;
  }
#if CONFIG_WOL_ENABLE_OTA
  start_updates();
#endif
}
}  // namespace updates
