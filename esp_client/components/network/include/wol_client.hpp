#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "credentials.hpp"
#include "protocol.hpp"
#include "tls_connection.hpp"

struct WolClientConfig {
  std::string host;
  int port;
};

// Keeps one authenticated session with the server's device port and serves its requests.
//
// Identity is persisted before enrollment; interrupted claims recover through DEVICE_AUTH.
class WolClient {
public:
  explicit WolClient(WolClientConfig config);

  [[noreturn]] void run();

private:
  bool auth_with_credentials(const Credentials& creds);
  bool claim_device(const std::string& token);
  void session_loop();
  bool handle(const Packet& packet);
  bool handle_wake_up(const Packet& packet);

  bool send(const Packet& packet);
  std::optional<Packet> await_reply();
  void backoff();

  WolClientConfig config_;
  TlsConnection conn_;
  uint32_t backoff_ms_;
  // Loaded from committed NVS before every connection attempt.
  std::optional<Credentials> creds_;
  bool auth_rejected_ = false;
};
