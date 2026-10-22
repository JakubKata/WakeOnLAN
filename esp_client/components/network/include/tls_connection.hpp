#pragma once

#include <string>

#include "esp_tls.h"

class TlsConnection {
public:
  enum class ReadResult { Line, Timeout, Closed, Error };

  TlsConnection() = default;
  ~TlsConnection();
  TlsConnection(const TlsConnection&) = delete;
  TlsConnection& operator=(const TlsConnection&) = delete;

  bool connect(const std::string& host, int port);
  void close();

  bool send_line(const std::string& line);
  // Strips the trailing newline. Fails when a line exceeds MAX_LINE_BYTES.
  ReadResult read_line(std::string& line, int timeout_ms);

private:
  esp_tls_t* tls_ = nullptr;
  std::string buffer_;
};
