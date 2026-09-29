#include "wol_client.hpp"

#include <algorithm>
#include <utility>

#include "credentials.hpp"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "magic_packet.hpp"
#include "wifi.hpp"

namespace {

constexpr const char* TAG = "wol_client";

constexpr int REPLY_TIMEOUT_MS = 10000;
constexpr int READ_TICK_MS = 5000;
// The server pings after 30 s of silence, so this only fires when it stops doing so.
constexpr int64_t IDLE_BEFORE_PING_US = 60 * 1000000LL;
constexpr int64_t PONG_TIMEOUT_US = 15 * 1000000LL;

constexpr uint32_t BACKOFF_MIN_MS = 2000;
constexpr uint32_t BACKOFF_MAX_MS = 60000;
constexpr int64_t STABLE_SESSION_US = 30 * 1000000LL;

constexpr int SAVE_ATTEMPTS = 3;
constexpr uint32_t SAVE_RETRY_DELAY_MS = 200;

bool is_nack(const Packet& packet, const std::string& code) {
  return packet.command == CMD_NACK && !packet.args.empty() && packet.args[0] == code;
}

const char* nack_reason(const Packet& packet) {
  return packet.args.empty() ? "?" : packet.args[0].c_str();
}

}  // namespace

WolClient::WolClient(WolClientConfig config) : config_(std::move(config)), backoff_ms_(BACKOFF_MIN_MS) {}

void WolClient::run() {
  for (;;) {
    std::string claim_token;
    const bool have_identity = load_identity();
    if (!have_identity && !pending_claim_token(claim_token)) {
      ESP_LOGW(TAG, "device is not paired; enter a fresh claim token on the console: claim <token>");
      ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
      continue;
    }

    wifi::wait_connected();
    if (!conn_.connect(config_.host, config_.port, config_.ca_pem, config_.skip_common_name)) {
      backoff();
      continue;
    }
    const bool authenticated = have_identity ? auth_with_credentials(*creds_) : claim_device(claim_token);
    if (!authenticated) {
      conn_.close();
      backoff();
      continue;
    }
    const int64_t session_start_us = esp_timer_get_time();
    session_loop();
    conn_.close();
    ESP_LOGI(TAG, "session ended");
    // A server that drops the session right away must not cause a reconnect loop.
    if (esp_timer_get_time() - session_start_us >= STABLE_SESSION_US) {
      backoff_ms_ = BACKOFF_MIN_MS;
    } else {
      backoff();
    }
  }
}

bool WolClient::load_identity() {
  if (!creds_) {
    Credentials stored;
    if (!credentials::load(stored)) return false;
    creds_ = std::move(stored);
    creds_persisted_ = true;
  }
  if (!creds_persisted_) persist_identity();
  return true;
}

bool WolClient::pending_claim_token(std::string& token) const {
  std::string candidate;
  if (!credentials::load_claim_token(candidate)) candidate = config_.claim_token;
  if (candidate.empty() || credentials::is_claim_token_used(candidate)) return false;
  token = std::move(candidate);
  return true;
}

void WolClient::forget_identity() {
  credentials::erase();
  creds_.reset();
  creds_persisted_ = false;
}

bool WolClient::persist_identity() {
  for (int attempt = 0; attempt < SAVE_ATTEMPTS && !creds_persisted_; ++attempt) {
    if (attempt > 0) vTaskDelay(pdMS_TO_TICKS(SAVE_RETRY_DELAY_MS));
    creds_persisted_ = credentials::save(*creds_) == ESP_OK;
  }
  if (!creds_persisted_) {
    ESP_LOGE(TAG, "credentials of %s are only in RAM and are lost on reboot", creds_->device_id.c_str());
  }
  return creds_persisted_;
}

bool WolClient::auth_with_credentials(const Credentials& creds) {
  if (!send(Packet(CMD_DEVICE_AUTH, {creds.device_id, creds.secret}))) return false;

  const std::optional<Packet> reply = await_reply();
  if (!reply) return false;
  if (reply->command == CMD_ACK) {
    ESP_LOGI(TAG, "authenticated as %s", creds.device_id.c_str());
    return true;
  }
  if (is_nack(*reply, ERR_INVALID_CREDENTIALS)) {
    ESP_LOGW(TAG, "server rejected stored credentials, forgetting them");
    forget_identity();
  } else {
    ESP_LOGW(TAG, "DEVICE_AUTH failed: %s", nack_reason(*reply));
  }
  return false;
}

bool WolClient::claim_device(const std::string& token) {
  if (!send(Packet(CMD_DEVICE_CLAIM, {token}))) return false;

  const std::optional<Packet> reply = await_reply();
  if (!reply) return false;
  if (reply->command == CMD_ACK && reply->args.size() >= 2) {
    creds_ = Credentials{reply->args[0], reply->args[1]};
    creds_persisted_ = false;
    ESP_LOGI(TAG, "paired as %s", creds_->device_id.c_str());
    persist_identity();
    credentials::mark_claim_token_used(token);
    return true;
  }
  if (is_nack(*reply, ERR_INVALID_TOKEN)) {
    ESP_LOGE(TAG, "claim token is invalid or expired");
    credentials::mark_claim_token_used(token);
  } else {
    ESP_LOGW(TAG, "DEVICE_CLAIM failed: %s", nack_reason(*reply));
  }
  return false;
}

void WolClient::session_loop() {
  int64_t last_rx_us = esp_timer_get_time();
  std::optional<int64_t> ping_sent_us;

  for (;;) {
    std::string line;
    const TlsConnection::ReadResult result = conn_.read_line(line, READ_TICK_MS);
    const int64_t now_us = esp_timer_get_time();

    if (result == TlsConnection::ReadResult::Timeout) {
      if (ping_sent_us) {
        if (now_us - *ping_sent_us >= PONG_TIMEOUT_US) {
          ESP_LOGW(TAG, "server stopped answering");
          return;
        }
      } else if (now_us - last_rx_us >= IDLE_BEFORE_PING_US) {
        if (!send(Packet(CMD_PING))) return;
        ping_sent_us = now_us;
      }
      continue;
    }
    if (result != TlsConnection::ReadResult::Line) {
      ESP_LOGW(TAG, "connection %s", result == TlsConnection::ReadResult::Closed ? "closed by server" : "failed");
      return;
    }

    last_rx_us = now_us;
    ping_sent_us.reset();

    const std::optional<Packet> packet = Packet::decode(line);
    if (!packet) {
      ESP_LOGW(TAG, "ignoring malformed line");
      continue;
    }
    if (!handle(*packet)) return;
  }
}

bool WolClient::handle(const Packet& packet) {
  if (packet.command == CMD_PING) return send(Packet(CMD_PONG));
  if (packet.command == CMD_PONG || packet.command == CMD_ACK) return true;
  if (packet.command == CMD_WAKE_UP) return handle_wake_up(packet);
  if (packet.command == CMD_SET_SECRET) return handle_set_secret(packet);
  if (packet.command == CMD_UNPAIRED) {
    ESP_LOGW(TAG, "device was removed from the account");
    forget_identity();
    return false;
  }
  if (packet.command == CMD_NACK) {
    ESP_LOGW(TAG, "server NACK: %s", nack_reason(packet));
    return true;
  }
  ESP_LOGW(TAG, "ignoring unknown command %s", packet.command.c_str());
  return true;
}

bool WolClient::handle_wake_up(const Packet& packet) {
  if (packet.args.size() < 2) {
    ESP_LOGW(TAG, "WAKE_UP without request id and MAC");
    return true;
  }
  const std::string& request_id = packet.args[0];
  wol::MacAddress mac;
  if (!wol::parse_mac(packet.args[1], mac)) {
    ESP_LOGW(TAG, "WAKE_UP with invalid MAC %s", packet.args[1].c_str());
    return true;
  }
  // Without WAKE_ACK the server reports device_unreachable to the app.
  if (wol::send_magic_packet(mac) != ESP_OK) return true;
  return send(Packet(CMD_WAKE_ACK, {request_id}));
}

bool WolClient::handle_set_secret(const Packet& packet) {
  if (packet.args.size() < 2 || packet.args[1].empty()) {
    ESP_LOGW(TAG, "SET_SECRET without request id and secret");
    return true;
  }
  // The server keeps accepting the old secret until SECRET_ACK, so it must be stored first.
  // Without working NVS the RAM copy is all there is, so the new secret is accepted anyway.
  if (creds_persisted_ && credentials::save_secret(packet.args[1]) != ESP_OK) return true;
  if (creds_) creds_->secret = packet.args[1];
  if (!creds_persisted_) persist_identity();
  ESP_LOGI(TAG, "device secret rotated");
  return send(Packet(CMD_SECRET_ACK, {packet.args[0]}));
}

bool WolClient::send(const Packet& packet) {
  return conn_.send_line(packet.encode());
}

std::optional<Packet> WolClient::await_reply() {
  std::string line;
  const TlsConnection::ReadResult result = conn_.read_line(line, REPLY_TIMEOUT_MS);
  if (result != TlsConnection::ReadResult::Line) {
    ESP_LOGW(TAG, "no reply from server");
    return std::nullopt;
  }
  std::optional<Packet> reply = Packet::decode(line);
  if (!reply || (reply->command != CMD_ACK && reply->command != CMD_NACK)) {
    ESP_LOGW(TAG, "unexpected reply from server");
    return std::nullopt;
  }
  return reply;
}

void WolClient::backoff() {
  const uint32_t jitter = esp_random() % (backoff_ms_ / 2 + 1);
  const uint32_t delay_ms = backoff_ms_ + jitter;
  ESP_LOGI(TAG, "retrying in %u ms", static_cast<unsigned>(delay_ms));
  vTaskDelay(pdMS_TO_TICKS(delay_ms));
  backoff_ms_ = std::min(backoff_ms_ * 2, BACKOFF_MAX_MS);
}
