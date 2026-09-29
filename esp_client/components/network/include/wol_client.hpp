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
  const char* ca_pem;
  bool skip_common_name;
  std::string claim_token;
};

// Keeps one authenticated session with the server's device port and serves its requests.
//
// Without credentials and without an unused claim token it does not connect at all;
// it waits for a task notification, sent after a new token is stored with
// credentials::save_claim_token().
class WolClient {
public:
  explicit WolClient(WolClientConfig config);

  [[noreturn]] void run();

private:
  bool load_identity();
  bool pending_claim_token(std::string& token) const;
  void forget_identity();
  bool persist_identity();

  bool auth_with_credentials(const Credentials& creds);
  bool claim_device(const std::string& token);
  void session_loop();
  bool handle(const Packet& packet);
  bool handle_wake_up(const Packet& packet);
  bool handle_set_secret(const Packet& packet);

  bool send(const Packet& packet);
  std::optional<Packet> await_reply();
  void backoff();

  WolClientConfig config_;
  TlsConnection conn_;
  uint32_t backoff_ms_;
  // The identity in use; kept in RAM as well so a failed NVS write does not unpair the device.
  std::optional<Credentials> creds_;
  bool creds_persisted_ = false;
};
