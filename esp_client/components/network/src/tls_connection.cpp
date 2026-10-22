#include "tls_connection.hpp"


#include "esp_log.h"
#include "esp_crt_bundle.h"
#include "esp_timer.h"
#include "lwip/sockets.h"
#include "protocol.hpp"

namespace {

constexpr const char* TAG = "tls";
constexpr int CONNECT_TIMEOUT_MS = 10000;
constexpr int SEND_TIMEOUT_MS = 10000;

bool retryable(ssize_t ret) {
  return ret == ESP_TLS_ERR_SSL_WANT_READ || ret == ESP_TLS_ERR_SSL_WANT_WRITE;
}

}  // namespace

TlsConnection::~TlsConnection() {
  close();
}

bool TlsConnection::connect(const std::string& host, int port) {
  close();

  esp_tls_cfg_t cfg = {};
  cfg.crt_bundle_attach = esp_crt_bundle_attach;
  cfg.timeout_ms = CONNECT_TIMEOUT_MS;
  cfg.skip_common_name = false;

  tls_ = esp_tls_init();
  if (tls_ == nullptr) {
    ESP_LOGE(TAG, "esp_tls_init failed");
    return false;
  }
  if (esp_tls_conn_new_sync(host.c_str(), host.size(), port, &cfg, tls_) != 1) {
    ESP_LOGW(TAG, "connection to %s:%d failed", host.c_str(), port);
    close();
    return false;
  }
  ESP_LOGI(TAG, "connected to %s:%d", host.c_str(), port);
  return true;
}

void TlsConnection::close() {
  if (tls_ != nullptr) {
    esp_tls_conn_destroy(tls_);
    tls_ = nullptr;
  }
  buffer_.clear();
}

bool TlsConnection::send_line(const std::string& line) {
  if (tls_ == nullptr || line.empty()) return false;

  // Each write blocks for up to SO_SNDTIMEO (cfg.timeout_ms) and then reports WANT_WRITE,
  // so without a deadline a server that stops reading would stall this task forever.
  const int64_t deadline_us = esp_timer_get_time() + static_cast<int64_t>(SEND_TIMEOUT_MS) * 1000;
  size_t written = 0;
  while (written < line.size()) {
    const ssize_t ret = esp_tls_conn_write(tls_, line.data() + written, line.size() - written);
    if (ret > 0) {
      written += static_cast<size_t>(ret);
    } else if (!retryable(ret)) {
      ESP_LOGW(TAG, "write failed: %d", static_cast<int>(ret));
      return false;
    } else if (esp_timer_get_time() >= deadline_us) {
      ESP_LOGW(TAG, "write timed out");
      return false;
    }
  }
  return true;
}

TlsConnection::ReadResult TlsConnection::read_line(std::string& line, int timeout_ms) {
  if (tls_ == nullptr) return ReadResult::Error;

  const int64_t deadline_us = esp_timer_get_time() + static_cast<int64_t>(timeout_ms) * 1000;
  for (;;) {
    const size_t newline = buffer_.find('\n');
    if (newline != std::string::npos) {
      line.assign(buffer_, 0, newline);
      buffer_.erase(0, newline + 1);
      if (!line.empty() && line.back() == '\r') line.pop_back();
      return ReadResult::Line;
    }
    if (buffer_.size() >= MAX_LINE_BYTES) {
      ESP_LOGW(TAG, "line exceeds %u bytes", static_cast<unsigned>(MAX_LINE_BYTES));
      return ReadResult::Error;
    }

    // Decrypted bytes may already sit inside mbedTLS, invisible to select().
    if (esp_tls_get_bytes_avail(tls_) <= 0) {
      const int64_t remaining_us = deadline_us - esp_timer_get_time();
      if (remaining_us <= 0) return ReadResult::Timeout;

      int fd = -1;
      if (esp_tls_get_conn_sockfd(tls_, &fd) != ESP_OK || fd < 0) return ReadResult::Error;

      fd_set readable;
      FD_ZERO(&readable);
      FD_SET(fd, &readable);
      timeval tv = {};
      tv.tv_sec = static_cast<time_t>(remaining_us / 1000000);
      tv.tv_usec = static_cast<suseconds_t>(remaining_us % 1000000);
      const int ready = select(fd + 1, &readable, nullptr, nullptr, &tv);
      if (ready < 0) return ReadResult::Error;
      if (ready == 0) return ReadResult::Timeout;
    }

    char chunk[512];
    const ssize_t ret = esp_tls_conn_read(tls_, chunk, sizeof(chunk));
    if (ret > 0) {
      buffer_.append(chunk, static_cast<size_t>(ret));
    } else if (ret == 0) {
      return ReadResult::Closed;
    } else if (!retryable(ret)) {
      ESP_LOGW(TAG, "read failed: %d", static_cast<int>(ret));
      return ReadResult::Error;
    }
  }
}
