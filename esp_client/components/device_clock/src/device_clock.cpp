#include "device_clock.hpp"

#include <algorithm>
#include <ctime>
#include <mutex>
#include <sys/time.h>

#include "esp_log.h"
#include "esp_netif_sntp.h"
#include "esp_timer.h"
#include "nvs.h"

namespace {
constexpr const char* TAG = "clock";
constexpr int64_t BUILD_FLOOR = 1767225600;  // 2026-01-01.
constexpr int64_t MAX_TIME = 4102444800;     // 2100-01-01.
std::mutex clock_mutex;
std::mutex sync_mutex;
bool ready = false;
int64_t phone_seconds = 0;
int64_t phone_monotonic_us = 0;

int64_t floor_time() {
  nvs_handle_t handle;
  int64_t saved = BUILD_FLOOR;
  if (nvs_open("wol", NVS_READONLY, &handle) == ESP_OK) {
    nvs_get_i64(handle, "time_floor", &saved);
    nvs_close(handle);
  }
  return std::max(saved, BUILD_FLOOR);
}

esp_err_t write_floor(int64_t value) {
  nvs_handle_t handle;
  esp_err_t result = nvs_open("wol", NVS_READWRITE, &handle);
  if (result != ESP_OK) return result;
  result = nvs_set_i64(handle, "time_floor", value);
  if (result == ESP_OK) result = nvs_commit(handle);
  nvs_close(handle);
  return result;
}

bool accepted(int64_t now) { return now >= floor_time() && now < MAX_TIME; }

bool set_time(int64_t seconds) {
  timeval value{};
  value.tv_sec = seconds;
  return settimeofday(&value, nullptr) == 0;
}
}  // namespace

namespace device_clock {
esp_err_t set_from_phone(int64_t unix_seconds, bool physical_recovery) {
  std::lock_guard<std::mutex> lock(clock_mutex);
  if (unix_seconds < BUILD_FLOOR || unix_seconds >= MAX_TIME) return ESP_ERR_INVALID_ARG;
  if (unix_seconds < floor_time()) {
    // Only physical presence plus the unique QR/SRP proof may repair a poisoned clock.
    if (!physical_recovery) return ESP_ERR_INVALID_ARG;
    const esp_err_t result = write_floor(unix_seconds);
    if (result != ESP_OK) return result;
  }
  if (!set_time(unix_seconds)) return ESP_FAIL;
  phone_seconds = unix_seconds;
  phone_monotonic_us = esp_timer_get_time();
  ready = true;
  return ESP_OK;
}

bool synchronize() {
  std::lock_guard<std::mutex> sync_lock(sync_mutex);
  {
    std::lock_guard<std::mutex> lock(clock_mutex);
    if (ready) return accepted(std::time(nullptr));
  }
  esp_sntp_config_t config = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
  if (esp_netif_sntp_init(&config) != ESP_OK) return false;
  const esp_err_t result = esp_netif_sntp_sync_wait(pdMS_TO_TICKS(15000));
  // Unauthenticated SNTP must not keep rewriting an established session's clock.
  esp_netif_sntp_deinit();
  std::lock_guard<std::mutex> lock(clock_mutex);
  if (phone_seconds != 0) {
    // A phone may have supplied trusted local time while the network sample was pending.
    if (!set_time(phone_seconds + (esp_timer_get_time() - phone_monotonic_us) / 1000000)) return false;
  } else if (result != ESP_OK) {
    ESP_LOGW(TAG, "waiting for time synchronization before TLS");
    return false;
  }
  if (!accepted(std::time(nullptr))) {
    ESP_LOGE(TAG, "clock is outside the accepted range; use physical setup to recover");
    return false;
  }
  ready = true;
  return true;
}

void checkpoint() {
  std::lock_guard<std::mutex> lock(clock_mutex);
  const int64_t now = std::time(nullptr);
  const int64_t previous = floor_time();
  if (now < previous || now >= MAX_TIME) return;
  // At most once per day, limiting flash wear on intermittent connections.
  if (now - previous >= 86400) write_floor(now);
}
}  // namespace device_clock
