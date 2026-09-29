#include "magic_packet.hpp"

#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <vector>

#include "esp_log.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"

namespace {

constexpr const char* TAG = "wol";
constexpr uint16_t WOL_PORT = 9;
constexpr int REPEAT = 3;
constexpr int REPEAT_DELAY_MS = 20;
constexpr size_t PACKET_SIZE = 6 + 16 * 6;

int hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

std::vector<uint32_t> broadcast_addresses() {
  std::vector<uint32_t> targets{htonl(INADDR_BROADCAST)};
  esp_netif_t* netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  esp_netif_ip_info_t info = {};
  if (netif != nullptr && esp_netif_get_ip_info(netif, &info) == ESP_OK && info.ip.addr != 0) {
    const uint32_t subnet = info.ip.addr | ~info.netmask.addr;
    if (subnet != targets.front()) targets.push_back(subnet);
  }
  return targets;
}

}  // namespace

namespace wol {

bool parse_mac(const std::string& text, MacAddress& out) {
  MacAddress mac = {};
  size_t digits = 0;
  for (const char c : text) {
    if (c == ':' || c == '-' || c == '.') continue;
    const int value = hex_value(c);
    if (value < 0 || digits >= 12) return false;
    mac[digits / 2] = static_cast<uint8_t>((mac[digits / 2] << 4) | value);
    ++digits;
  }
  if (digits != 12 || (mac[0] & 0x01) != 0) return false;
  out = mac;
  return true;
}

esp_err_t send_magic_packet(const MacAddress& mac) {
  std::array<uint8_t, PACKET_SIZE> packet;
  std::memset(packet.data(), 0xFF, 6);
  for (size_t i = 0; i < 16; ++i) {
    std::memcpy(packet.data() + 6 + i * mac.size(), mac.data(), mac.size());
  }

  const int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0) {
    ESP_LOGE(TAG, "socket failed: errno %d", errno);
    return ESP_FAIL;
  }
  const int enable = 1;
  setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(enable));

  const std::vector<uint32_t> targets = broadcast_addresses();
  int sent = 0;
  for (int round = 0; round < REPEAT; ++round) {
    for (const uint32_t address : targets) {
      sockaddr_in dest = {};
      dest.sin_family = AF_INET;
      dest.sin_port = htons(WOL_PORT);
      dest.sin_addr.s_addr = address;
      const ssize_t ret =
          sendto(sock, packet.data(), packet.size(), 0, reinterpret_cast<const sockaddr*>(&dest), sizeof(dest));
      if (ret == static_cast<ssize_t>(packet.size())) {
        ++sent;
      } else {
        ESP_LOGW(TAG, "sendto failed: errno %d", errno);
      }
    }
    if (round + 1 < REPEAT) vTaskDelay(pdMS_TO_TICKS(REPEAT_DELAY_MS));
  }
  close(sock);

  if (sent == 0) return ESP_FAIL;
  ESP_LOGI(TAG, "magic packet sent to %02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4],
           mac[5]);
  return ESP_OK;
}

}  // namespace wol
