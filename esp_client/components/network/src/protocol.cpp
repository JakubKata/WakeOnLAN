#include "protocol.hpp"

#include <utility>

#include "cJSON.h"

namespace {

// cJSON parses recursively and allows 1000 levels, far more than the task stack holds.
// Valid frames are {"CMD":[...]}, i.e. two levels.
constexpr int MAX_NESTING = 4;

bool nesting_within_limit(const std::string& line) {
  int depth = 0;
  bool in_string = false;
  bool escaped = false;
  for (const char c : line) {
    if (in_string) {
      if (escaped) {
        escaped = false;
      } else if (c == '\\') {
        escaped = true;
      } else if (c == '"') {
        in_string = false;
      }
    } else if (c == '"') {
      in_string = true;
    } else if (c == '[' || c == '{') {
      if (++depth > MAX_NESTING) return false;
    } else if (c == ']' || c == '}') {
      --depth;
    }
  }
  return true;
}

std::string arg_to_string(const cJSON* item) {
  if (cJSON_IsString(item)) return item->valuestring;
  char* text = cJSON_PrintUnformatted(item);
  std::string out = text ? text : "";
  cJSON_free(text);
  return out;
}

}  // namespace

Packet::Packet(std::string command, std::vector<std::string> args)
  : command(std::move(command)), args(std::move(args)) {}

std::string Packet::encode() const {
  cJSON* root = cJSON_CreateObject();
  if (root == nullptr) return {};

  std::string out;
  cJSON* array = cJSON_AddArrayToObject(root, command.c_str());
  bool ok = array != nullptr;
  for (size_t i = 0; ok && i < args.size(); ++i) {
    cJSON* item = cJSON_CreateString(args[i].c_str());
    ok = item != nullptr && cJSON_AddItemToArray(array, item);
  }
  if (ok) {
    char* text = cJSON_PrintUnformatted(root);
    if (text != nullptr) {
      out = text;
      out += '\n';
      cJSON_free(text);
    }
  }
  cJSON_Delete(root);
  return out;
}

std::optional<Packet> Packet::decode(const std::string& line) {
  if (!nesting_within_limit(line)) return std::nullopt;
  cJSON* root = cJSON_ParseWithLength(line.data(), line.size());
  if (root == nullptr) return std::nullopt;

  std::optional<Packet> packet;
  const cJSON* entry = root->child;
  if (cJSON_IsObject(root) && entry != nullptr && entry->next == nullptr && entry->string != nullptr &&
      cJSON_IsArray(entry)) {
    std::vector<std::string> args;
    const cJSON* item = nullptr;
    cJSON_ArrayForEach(item, entry) {
      args.push_back(arg_to_string(item));
    }
    packet.emplace(entry->string, std::move(args));
  }
  cJSON_Delete(root);
  return packet;
}
