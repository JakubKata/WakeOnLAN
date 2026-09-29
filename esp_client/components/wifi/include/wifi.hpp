#pragma once

#include "esp_err.h"
#include "freertos/FreeRTOS.h"

namespace wifi {

// Requires nvs_flash_init(). Reconnects on its own after every disconnect.
esp_err_t start(const char* ssid, const char* password);
void wait_connected();

}  // namespace wifi
