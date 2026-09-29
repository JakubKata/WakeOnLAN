#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

// Wire format shared with the server: one JSON object per line, {"COMMAND":[arg,...]}.
constexpr size_t MAX_LINE_BYTES = 4096;

class Packet {
public:
  std::string command;
  std::vector<std::string> args;

  Packet(std::string command, std::vector<std::string> args = {});
  std::string encode() const;
  static std::optional<Packet> decode(const std::string& line);
};

inline const std::string CMD_ACK = "ACK";
inline const std::string CMD_NACK = "NACK";
inline const std::string CMD_PING = "PING";
inline const std::string CMD_PONG = "PONG";

inline const std::string CMD_DEVICE_CLAIM = "DEVICE_CLAIM";
inline const std::string CMD_DEVICE_AUTH = "DEVICE_AUTH";
inline const std::string CMD_WAKE_UP = "WAKE_UP";
inline const std::string CMD_WAKE_ACK = "WAKE_ACK";
inline const std::string CMD_SET_SECRET = "SET_SECRET";
inline const std::string CMD_SECRET_ACK = "SECRET_ACK";
inline const std::string CMD_UNPAIRED = "UNPAIRED";

inline const std::string ERR_INVALID_CREDENTIALS = "invalid_credentials";
inline const std::string ERR_INVALID_TOKEN = "invalid_token";
