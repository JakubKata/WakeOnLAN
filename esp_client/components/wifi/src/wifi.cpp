#include "wifi.hpp"

#include <atomic>

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
std::atomic<bool> provisioning{false};

void reconnect() {
  wifi_config_t config{};
  if (!provisioning.load() && esp_wifi_get_config(WIFI_IF_STA, &config) == ESP_OK && config.sta.ssid[0]) {
    esp_wifi_connect();
  }
}

void on_event(void*, esp_event_base_t base, int32_t id, void* data) {
  if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
    reconnect();
  } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
    xEventGroupClearBits(events, CONNECTED_BIT);
    const auto* event = static_cast<const wifi_event_sta_disconnected_t*>(data);
    ESP_LOGW(TAG, "disconnected (reason %d), reconnecting", event->reason);
    reconnect();
  } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
    const auto* event = static_cast<const ip_event_got_ip_t*>(data);
    ESP_LOGI(TAG, "got ip " IPSTR, IP2STR(&event->ip_info.ip));
    xEventGroupSetBits(events, CONNECTED_BIT);
  } else if (base == IP_EVENT && id == IP_EVENT_STA_LOST_IP) {
    xEventGroupClearBits(events, CONNECTED_BIT);
  }
}

}  // namespace

namespace wifi {

esp_err_t start() {
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

  ESP_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_STA), TAG, "set mode");
  ESP_RETURN_ON_ERROR(esp_wifi_start(), TAG, "esp_wifi_start");
  return ESP_OK;
}

void set_provisioning(bool active) {
  provisioning.store(active);
  if (!active) reconnect();
}

void wait_connected() {
  xEventGroupWaitBits(events, CONNECTED_BIT, pdFALSE, pdTRUE, portMAX_DELAY);
}

}  // namespace wifi
