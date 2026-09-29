#include <cstdio>
#include <cstring>

#include "credentials.hpp"
#include "esp_console.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "sdkconfig.h"
#include "wifi.hpp"
#include "wol_client.hpp"

extern const char server_crt_start[] asm("_binary_server_crt_start");

#if !CONFIG_NVS_ENCRYPTION
#warning "CONFIG_NVS_ENCRYPTION is off: the device secret is stored in plain text"
#endif

#if CONFIG_WOL_SKIP_CN_CHECK && CONFIG_SECURE_BOOT
#error "CONFIG_WOL_SKIP_CN_CHECK is for development only and must be off in release builds"
#endif

namespace {

constexpr const char* TAG = "main";
constexpr uint32_t CLIENT_STACK_BYTES = 10240;
constexpr size_t MIN_TOKEN_LENGTH = 16;
constexpr size_t MAX_TOKEN_LENGTH = 128;

#ifdef CONFIG_WOL_SKIP_CN_CHECK
constexpr bool SKIP_CN_CHECK = true;
#else
constexpr bool SKIP_CN_CHECK = false;
#endif

TaskHandle_t client_task_handle = nullptr;

void init_nvs() {
  // With CONFIG_NVS_ENCRYPTION this reads (or on first boot generates) the keys in nvs_keys.
  esp_err_t err = nvs_flash_init();
  if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_LOGW(TAG, "NVS partition is unusable, erasing it");
    ESP_ERROR_CHECK(nvs_flash_erase());
    err = nvs_flash_init();
  }
  ESP_ERROR_CHECK(err);
}

bool is_token(const char* value) {
  const size_t length = std::strlen(value);
  if (length < MIN_TOKEN_LENGTH || length > MAX_TOKEN_LENGTH) return false;
  for (size_t i = 0; i < length; ++i) {
    const char c = value[i];
    const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
    if (!ok) return false;
  }
  return true;
}

int claim_command(int argc, char** argv) {
  if (argc != 2 || !is_token(argv[1])) {
    std::printf("usage: claim <token from the app>\n");
    return 1;
  }
  if (credentials::save_claim_token(argv[1]) != ESP_OK) {
    std::printf("could not store the claim token\n");
    return 1;
  }
  std::printf("claim token stored, pairing...\n");
  if (client_task_handle != nullptr) xTaskNotifyGive(client_task_handle);
  return 0;
}

void start_console() {
  esp_console_repl_t* repl = nullptr;
  esp_console_repl_config_t repl_config = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
  repl_config.prompt = "wol>";
  esp_console_dev_uart_config_t uart_config = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_console_new_repl_uart(&uart_config, &repl_config, &repl));

  esp_console_cmd_t claim = {};
  claim.command = "claim";
  claim.help = "Pair this device using a claim token created in the app";
  claim.hint = "<token>";
  claim.func = &claim_command;
  ESP_ERROR_CHECK(esp_console_cmd_register(&claim));
  ESP_ERROR_CHECK(esp_console_start_repl(repl));
}

void client_task(void*) {
  WolClient client(WolClientConfig{
    CONFIG_WOL_SERVER_HOST,
    CONFIG_WOL_SERVER_PORT,
    server_crt_start,
    SKIP_CN_CHECK,
    CONFIG_WOL_CLAIM_TOKEN,
  });
  client.run();
}

}  // namespace

extern "C" void app_main() {
  init_nvs();
  ESP_ERROR_CHECK(wifi::start(CONFIG_WOL_WIFI_SSID, CONFIG_WOL_WIFI_PASSWORD));
  xTaskCreate(client_task, "wol_client", CLIENT_STACK_BYTES, nullptr, 5, &client_task_handle);
  start_console();
}
