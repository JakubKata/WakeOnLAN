#include <cstdlib>

#include "credentials.hpp"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "onboarding.hpp"
#include "sdkconfig.h"
#include "wifi.hpp"
#include "updates.hpp"
#include "wol_client.hpp"

#if !CONFIG_NVS_ENCRYPTION
#error "Wake-on-LAN credentials require encrypted NVS"
#endif

namespace {
void client_task(void*) {
  WolClient client(WolClientConfig{CONFIG_WOL_SERVER_HOST, CONFIG_WOL_SERVER_PORT});
  client.run();
}
}  // namespace

extern "C" void app_main() {
  // Never erase NVS on an initialization error: that would discard ownership and factory PoP.
  // The SDK debug-level provisioning logs contain parts of Wi-Fi credentials.
  esp_log_level_set("wifi_prov_mgr", ESP_LOG_WARN);
  ESP_ERROR_CHECK(nvs_flash_init());
  ESP_ERROR_CHECK(wifi::start());
  // Wi-Fi is running, so esp_fill_random has hardware entropy available.
  ESP_ERROR_CHECK(credentials::ensure_identity());
  ESP_ERROR_CHECK(onboarding::start());
  updates::start();
  if (xTaskCreate(client_task, "wol_client", 12288, nullptr, 5, nullptr) != pdPASS) {
    ESP_LOGE("main", "cannot start cloud client");
    abort();
  }
}
