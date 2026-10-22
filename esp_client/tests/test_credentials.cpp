// Host test of the production storage code. NVS uses staged snapshots and durable
// commits, with failure injection on both sides of the persistence boundary.
#include "credentials.hpp"
#include "nvs.h"
#include "onboarding_request.hpp"
#include "release_version.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/sha.h>

namespace {
struct Entry { bool blob; std::vector<unsigned char> bytes; };
using Store = std::map<std::string, Entry>;
Store durable;
std::map<nvs_handle_t, Store> handles;
nvs_handle_t next_handle = 1;
int commits = 0, writes = 0, random_calls = 0, fail_commit = 0;
bool persist_on_failure = false, fail_open = false, fail_write = false;

void check(bool success, const char* message) {
  if (!success) throw std::runtime_error(message);
}

void reset() {
  durable.clear(); handles.clear(); commits = writes = random_calls = fail_commit = 0;
  persist_on_failure = fail_open = fail_write = false;
}

void reboot() {
  check(handles.empty(), "NVS handle leaked");
  fail_commit = 0; persist_on_failure = fail_open = fail_write = false;
}

void legacy(const std::string& key, const std::string& value) {
  std::vector<unsigned char> bytes(value.begin(), value.end());
  bytes.push_back(0);
  durable[key] = Entry{false, bytes};
}

Credentials load() {
  Credentials result;
  check(credentials::load(result), "identity must be readable");
  return result;
}

void same_identity(const Credentials& expected) {
  const auto actual = load();
  check(actual.device_id == expected.device_id && actual.secret == expected.secret,
        "device identity changed");
}

std::string b64url(const unsigned char* bytes, size_t length) {
  std::vector<unsigned char> encoded(4 * ((length + 2) / 3) + 1);
  const int count = EVP_EncodeBlock(encoded.data(), bytes, static_cast<int>(length));
  std::string result(reinterpret_cast<char*>(encoded.data()), count);
  for (char& value : result) { if (value == '+') value = '-'; if (value == '/') value = '_'; }
  while (!result.empty() && result.back() == '=') result.pop_back();
  return result;
}

void test_identity_and_noop_writes() {
  reset();
  check(credentials::ensure_identity() == ESP_OK, "initial enrollment identity");
  const auto first = load();
  check(!first.paired && first.claim_token.empty(), "fresh state");
  std::array<unsigned char, 32> secret{}, hash{};
  for (size_t i = 0; i < secret.size(); ++i) secret[i] = static_cast<unsigned char>(i + 1);
  SHA256(secret.data(), secret.size(), hash.data());
  check(first.secret == b64url(secret.data(), secret.size()) &&
        first.device_id == b64url(hash.data(), hash.size()), "self-certifying identity");
  const int written = writes, committed = commits;
  reboot();
  check(credentials::ensure_identity() == ESP_OK, "reboot preserves identity");
  same_identity(first);
  check(random_calls == 1 && writes == written && commits == committed, "no regeneration or flash wear");
}

void test_claim_replacement_and_confirmation() {
  reset(); check(credentials::ensure_identity() == ESP_OK, "create identity");
  const auto identity = load();
  check(credentials::save_claim_token("old-claim-token-1234") == ESP_OK, "old claim");
  const std::string old = load().claim_token;
  check(credentials::save_claim_token("new-claim-token-5678") == ESP_OK, "new claim");
  check(credentials::clear_claim_token(old) == ESP_OK, "old rejection");
  check(load().claim_token == "new-claim-token-5678", "old rejection erased newer claim");
  check(credentials::mark_paired(old) == ESP_OK, "old success");
  check(load().paired && load().claim_token == "new-claim-token-5678", "old success erased newer claim");
  check(credentials::mark_paired("new-claim-token-5678") == ESP_OK, "new success");
  check(load().paired && load().claim_token.empty(), "confirmation must clear matching pending claim");
  const int written = writes;
  check(credentials::mark_paired("") == ESP_OK && writes == written, "reconnect rewrites unchanged identity");
  check(credentials::mark_unpaired("") == ESP_OK, "owner removal");
  reboot(); same_identity(identity);
  check(!load().paired && load().claim_token.empty(), "owner removal state");
}

void test_failed_update_is_recoverable() {
  reset(); check(credentials::ensure_identity() == ESP_OK, "create identity");
  check(credentials::save_claim_token("pending-claim-token") == ESP_OK, "save pending");
  const auto before = load();
  fail_commit = commits + 1;
  check(credentials::mark_paired(before.claim_token) != ESP_OK, "commit failure must propagate");
  reboot(); same_identity(before);
  check(!load().paired && load().claim_token == before.claim_token, "uncommitted confirmation survived reboot");
  check(credentials::mark_paired(before.claim_token) == ESP_OK && load().paired, "retry confirmation");

  check(credentials::save_claim_token("next-pending-token") == ESP_OK, "save next");
  fail_write = true;
  check(credentials::clear_claim_token("next-pending-token") != ESP_OK, "write failure must propagate");
  reboot(); check(load().claim_token == "next-pending-token", "failed write damaged pending token");
}

void test_ambiguous_commit_keeps_complete_identity() {
  reset(); fail_commit = 1; persist_on_failure = true;
  check(credentials::ensure_identity() != ESP_OK, "ambiguous initial commit must report error");
  reboot(); const auto stored = load();
  check(credentials::ensure_identity() == ESP_OK, "recover ambiguous initial commit");
  same_identity(stored); check(random_calls == 1, "ambiguous commit regenerated identity");

  reset(); fail_commit = 1;
  check(credentials::ensure_identity() != ESP_OK, "failed initial commit must report error");
  reboot(); Credentials absent;
  check(!credentials::load(absent), "failed first commit exposed partial credentials");
  check(credentials::ensure_identity() == ESP_OK && load().device_id.size() == 43, "retry initial identity");
}

void test_legacy_migration_and_interrupted_cleanup() {
  reset();
  legacy("device_id", "legacy-device-id-123"); legacy("secret", "legacy-device-secret-456");
  legacy("claim", "obsolete-claim-token"); legacy("used_claim", "obsolete-used-token");
  fail_commit = 2;
  check(credentials::ensure_identity() != ESP_OK, "cleanup commit error must propagate");
  reboot(); const auto migrated = load();
  check(migrated.device_id == "legacy-device-id-123" && migrated.secret == "legacy-device-secret-456"
        && migrated.paired, "migration lost ownership");
  check(credentials::ensure_identity() == ESP_OK, "recover interrupted migration cleanup");
  same_identity(migrated); check(random_calls == 0, "migration generated new identity");

  reset(); legacy("device_id", "legacy-device-id-123"); legacy("secret", "legacy-device-secret-456");
  check(credentials::ensure_identity() == ESP_OK, "legacy migration");
  check(durable.count("device_id") == 0 && durable.count("secret") == 0, "legacy keys not cleaned up");
}

void test_damaged_identity_is_never_replaced() {
  reset(); durable["identity"] = Entry{true, {0, 1, 2}};
  check(credentials::ensure_identity() != ESP_OK, "corrupt record accepted");
  check(random_calls == 0 && writes == 0 && durable.at("identity").bytes.size() == 3,
        "corrupt identity replaced");

  reset(); legacy("device_id", "half-written-legacy-id");
  check(credentials::ensure_identity() != ESP_OK && random_calls == 0 && writes == 0,
        "partial legacy identity replaced");

  reset(); fail_open = true;
  check(credentials::ensure_identity() != ESP_OK && random_calls == 0, "NVS error caused regeneration");
}

void test_claim_capacity_preserves_durable_state() {
  reset(); check(credentials::ensure_identity() == ESP_OK, "create identity");
  const auto identity = load();
  const std::string maximum(128, 'a');
  check(credentials::save_claim_token(maximum) == ESP_OK, "maximum claim rejected");
  const int written = writes, committed = commits;
  check(credentials::save_claim_token(maximum + "b") == ESP_ERR_INVALID_ARG,
        "oversized claim accepted");
  check(writes == written && commits == committed, "oversized claim modified NVS");
  reboot(); same_identity(identity);
  check(load().claim_token == maximum, "oversized claim destroyed previous token");
  check(credentials::clear_claim_token(maximum) == ESP_OK && load().claim_token.empty(),
        "maximum claim cannot be consumed");
}

void test_complete_but_invalid_records_are_rejected() {
  reset(); check(credentials::ensure_identity() == ESP_OK, "create identity");
  const auto valid = durable.at("identity");
  // The persisted v1 layout is two flag bytes followed by three 129-byte C strings.
  check(valid.bytes.size() == 389, "unexpected v1 wire layout");
  const auto reject = [&](std::vector<unsigned char> bytes) {
    durable["identity"] = Entry{true, std::move(bytes)};
    const auto before = durable.at("identity").bytes;
    const int written = writes, generated = random_calls;
    Credentials sentinel{"keep-id", "keep-secret", "keep-claim", true};
    check(!credentials::load(sentinel), "invalid complete record accepted");
    check(sentinel.device_id == "keep-id" && sentinel.secret == "keep-secret" &&
          sentinel.claim_token == "keep-claim" && sentinel.paired,
          "failed load exposed partial record");
    check(credentials::ensure_identity() != ESP_OK, "invalid record silently repaired");
    check(writes == written && random_calls == generated &&
          durable.at("identity").bytes == before, "invalid identity was overwritten");
  };
  auto invalid = valid.bytes; invalid[0] = 2; reject(invalid);
  invalid = valid.bytes; invalid[1] = 2; reject(invalid);
  for (const size_t start : {size_t{2}, size_t{131}, size_t{260}}) {
    invalid = valid.bytes;
    std::fill(invalid.begin() + start, invalid.begin() + start + 129, 'x');
    reject(invalid);
  }
  for (const size_t start : {size_t{2}, size_t{131}}) {
    invalid = valid.bytes; invalid[start] = 0; reject(invalid);
  }
}

void test_failed_legacy_commit_preserves_recoverable_keys() {
  reset();
  legacy("device_id", "legacy-device-id-123"); legacy("secret", "legacy-device-secret-456");
  fail_commit = 1;
  check(credentials::ensure_identity() != ESP_OK, "failed migration commit reported success");
  check(durable.count("identity") == 0 && durable.count("device_id") == 1 &&
        durable.count("secret") == 1, "failed migration destroyed legacy identity");
  reboot();
  check(credentials::ensure_identity() == ESP_OK, "migration retry failed");
  const auto migrated = load();
  check(migrated.device_id == "legacy-device-id-123" && migrated.secret == "legacy-device-secret-456"
        && migrated.paired && random_calls == 0, "migration retry changed legacy identity");
}

void test_ota_version_gate() {
  check(updates::newer_version("2.1.0", "2.0.0"), "minor update rejected");
  check(updates::newer_version("3.0.0", "2.99.99"), "major update rejected");
  check(updates::newer_version("2.0.1", "2.0.0"), "patch update rejected");
  check(!updates::newer_version("2.0.0", "2.0.0"), "same image accepted");
  check(!updates::newer_version("1.99.99", "2.0.0"), "downgrade accepted");
  const char* malformed[] = {"-3.0.0", "+3.0.0", " 3.0.0", "3.0.0 ", "3.0.0-git123",
    "4294967296.0.0", "3.4294967296.0", "3.0.4294967296", "3.0", "3", "", "3..0", "3.0.0.1"};
  for (const char* version : malformed) {
    check(!updates::newer_version(version, "2.0.0"), "malformed candidate version accepted");
    check(!updates::newer_version("9.0.0", version), "malformed installed version accepted");
  }
}

void test_onboarding_request_boundaries() {
  // This is a complexity/NUL precheck; cJSON and the endpoint schema validate
  // JSON syntax and permitted fields after it succeeds.
  const char* accepted[] = {
    R"({"op":"info"})",
    R"({"op":"claim","token":"claim-token","time":1800000000})",
    R"({"value":"braces{} and brackets[] inside strings"})",
    R"({"value":"escaped\"quote and \\backslash"})",
    R"({"value":"\\u0000"})",
  };
  for (const char* request : accepted)
    check(onboarding::bounded_request(request), "flat request rejected");
  const char* rejected[] = {
    "", R"({"value":{"nested":true}})", R"({"value":[]})", "[]",
    R"({"value":"\u0000"})", R"({"value":"prefix\u0000suffix"})",
    "{", "}", R"({"value":"unterminated})", R"({"value":"trailing\)",
  };
  for (const char* request : rejected)
    check(!onboarding::bounded_request(request), "unsafe request precheck passed");
  const std::string raw_nul("{\"value\":\"before\0after\"}", 24);
  check(!onboarding::bounded_request(raw_nul), "raw NUL accepted");
  const std::string maximum = "{\"value\":\"" + std::string(500, 'a') + "\"}";
  check(maximum.size() == 512 && onboarding::bounded_request(maximum), "maximum flat request rejected");
  check(!onboarding::bounded_request(maximum + " "), "oversized request accepted");
}
}  // namespace

esp_err_t nvs_open(const char* name, int, nvs_handle_t* handle) {
  if (fail_open || std::string(name) != "wol") return ESP_FAIL;
  *handle = next_handle++; handles[*handle] = durable; return ESP_OK;
}
void nvs_close(nvs_handle_t handle) { handles.erase(handle); }
esp_err_t read_entry(nvs_handle_t handle, const char* key, void* value, size_t* length, bool blob) {
  const auto& store = handles.at(handle); auto found = store.find(key);
  if (found == store.end()) return ESP_ERR_NVS_NOT_FOUND;
  if (found->second.blob != blob) return ESP_ERR_NVS_TYPE_MISMATCH;
  const auto& bytes = found->second.bytes;
  if (!value) { *length = bytes.size(); return ESP_OK; }
  if (*length < bytes.size()) { *length = bytes.size(); return ESP_ERR_NVS_INVALID_LENGTH; }
  std::memcpy(value, bytes.data(), bytes.size()); *length = bytes.size(); return ESP_OK;
}
esp_err_t nvs_get_blob(nvs_handle_t handle, const char* key, void* value, size_t* length) {
  return read_entry(handle, key, value, length, true);
}
esp_err_t nvs_get_str(nvs_handle_t handle, const char* key, char* value, size_t* length) {
  return read_entry(handle, key, value, length, false);
}
esp_err_t nvs_set_blob(nvs_handle_t handle, const char* key, const void* value, size_t length) {
  if (fail_write) return ESP_FAIL;
  const auto* bytes = static_cast<const unsigned char*>(value);
  handles.at(handle)[key] = Entry{true, std::vector<unsigned char>(bytes, bytes + length)}; ++writes; return ESP_OK;
}
esp_err_t nvs_erase_key(nvs_handle_t handle, const char* key) {
  return handles.at(handle).erase(key) ? ESP_OK : ESP_ERR_NVS_NOT_FOUND;
}
esp_err_t nvs_commit(nvs_handle_t handle) {
  ++commits;
  if (commits == fail_commit) {
    if (persist_on_failure) durable = handles.at(handle);
    return ESP_FAIL;
  }
  durable = handles.at(handle); return ESP_OK;
}
void esp_fill_random(void* output, size_t length) {
  ++random_calls; auto* bytes = static_cast<unsigned char*>(output);
  for (size_t i = 0; i < length; ++i) bytes[i] = static_cast<unsigned char>(i + random_calls);
}
int mbedtls_sha256(const unsigned char* input, size_t length, unsigned char* output, int is224) {
  return is224 || SHA256(input, length, output) == nullptr ? -1 : 0;
}
int mbedtls_base64_encode(unsigned char* output, size_t capacity, size_t* written,
                          const unsigned char* input, size_t length) {
  if (capacity < 4 * ((length + 2) / 3) + 1) return -1;
  *written = EVP_EncodeBlock(output, input, static_cast<int>(length)); return 0;
}
void mbedtls_platform_zeroize(void* output, size_t length) {
  auto* bytes = static_cast<volatile unsigned char*>(output); while (length--) *bytes++ = 0;
}

int main() {
  const std::pair<const char*, void (*)()> cases[] = {
    {"identity/no-op writes", test_identity_and_noop_writes},
    {"claim replacement/confirmation", test_claim_replacement_and_confirmation},
    {"failed update recovery", test_failed_update_is_recoverable},
    {"ambiguous commit", test_ambiguous_commit_keeps_complete_identity},
    {"legacy migration", test_legacy_migration_and_interrupted_cleanup},
    {"damaged identity retention", test_damaged_identity_is_never_replaced},
    {"claim capacity and durable state", test_claim_capacity_preserves_durable_state},
    {"invalid complete record retention", test_complete_but_invalid_records_are_rejected},
    {"failed legacy commit recovery", test_failed_legacy_commit_preserves_recoverable_keys},
    {"OTA version gate", test_ota_version_gate},
    {"onboarding parser boundaries", test_onboarding_request_boundaries},
  };
  for (const auto& [name, test] : cases) {
    try { test(); check(handles.empty(), "NVS handle leaked"); }
    catch (const std::exception& error) { std::cerr << "FAIL " << name << ": " << error.what() << '\n'; return 1; }
    std::cout << "PASS " << name << '\n';
  }
  return 0;
}
