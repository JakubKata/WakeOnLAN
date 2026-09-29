#include "wifi.hpp"

#include <algorithm>
#include <cstring>

#include "esp_check.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/event_groups.h"

namespace {

constexpr const char* TAG = "wifi";
constexpr EventBits_t CONNECTED_BIT = BIT0;

EventGroupHandle_t events = nullptr;

void on_event(void*, esp_event_base_t base, int32_t id, void* data) {
  if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
    esp_wifi_connect();
  } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
    xEventGroupClearBits(events, CONNECTED_BIT);
    const auto* event = static_cast<const wifi_event_sta_disconnected_t*>(data);
    ESP_LOGW(TAG, "disconnected (reason %d), reconnecting", event->reason);
    esp_wifi_connect();
  } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
    const auto* event = static_cast<const ip_event_got_ip_t*>(data);
    ESP_LOGI(TAG, "got ip " IPSTR, IP2STR(&event->ip_info.ip));
    xEventGroupSetBits(events, CONNECTED_BIT);
  } else if (base == IP_EVENT && id == IP_EVENT_STA_LOST_IP) {
    xEventGroupClearBits(events, CONNECTED_BIT);
  }
}

void copy_field(uint8_t* dest, size_t capacity, const char* src) {
  std::memcpy(dest, src, std::min(std::strlen(src), capacity));
}

}  // namespace

namespace wifi {

esp_err_t start(const char* ssid, const char* password) {
  if (std::strlen(ssid) == 0) {
    ESP_LOGE(TAG, "WiFi SSID is not configured");
    return ESP_ERR_INVALID_ARG;
  }

  events = xEventGroupCreate();
  if (events == nullptr) return ESP_ERR_NO_MEM;

  ESP_RETURN_ON_ERROR(esp_netif_init(), TAG, "esp_netif_init");
  ESP_RETURN_ON_ERROR(esp_event_loop_create_default(), TAG, "event loop");
  esp_netif_create_default_wifi_sta();

  wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
  ESP_RETURN_ON_ERROR(esp_wifi_init(&init), TAG, "esp_wifi_init");
  ESP_RETURN_ON_ERROR(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_event, nullptr, nullptr),
                      TAG, "wifi handler");
  ESP_RETURN_ON_ERROR(esp_event_handler_instance_register(IP_EVENT, ESP_EVENT_ANY_ID, on_event, nullptr, nullptr),
                      TAG, "ip handler");

  wifi_config_t config = {};
  copy_field(config.sta.ssid, sizeof(config.sta.ssid), ssid);
  copy_field(config.sta.password, sizeof(config.sta.password), password);
  config.sta.threshold.authmode = std::strlen(password) == 0 ? WIFI_AUTH_OPEN : WIFI_AUTH_WPA2_PSK;

  ESP_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_STA), TAG, "set mode");
  ESP_RETURN_ON_ERROR(esp_wifi_set_config(WIFI_IF_STA, &config), TAG, "set config");
  ESP_RETURN_ON_ERROR(esp_wifi_start(), TAG, "esp_wifi_start");
  ESP_LOGI(TAG, "connecting to %s", ssid);
  return ESP_OK;
}

void wait_connected() {
  xEventGroupWaitBits(events, CONNECTED_BIT, pdFALSE, pdTRUE, portMAX_DELAY);
}

}  // namespace wifi
