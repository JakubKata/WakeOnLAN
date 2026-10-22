// Reuse the fault-injected NVS implementation to exercise the actual storage API.
#define main storage_regression_main
#include "test_credentials.cpp"
#undef main

namespace {
const std::string OLD_CLAIM = "AAECAwQFBgcICQoLDA0ODw";
const std::string NEW_CLAIM = "EBESExQVFhcYGRobHB0eHw";

Credentials paired_identity() {
  reset();
  check(credentials::ensure_identity() == ESP_OK, "create identity");
  check(credentials::mark_paired("") == ESP_OK, "original owner enrolled");
  return load();
}

void verify_state(const Credentials& identity, bool paired, const std::string& claim) {
  same_identity(identity);
  const auto stored = load();
  check(stored.paired == paired, "unexpected paired state");
  check(stored.claim_token == claim, "pending claim changed unexpectedly");
}

void delayed_unpair(const std::string& session_claim) {
  const auto identity = paired_identity();
  if (!session_claim.empty()) {
    check(credentials::save_claim_token(session_claim) == ESP_OK, "old pending claim");
  }
  const auto session = load();
  // The original owner has deleted the device server-side. During physical
  // setup a new owner's claim arrives over BLE before the old TLS session's
  // delayed UNPAIRED is processed by WolClient::handle.
  check(credentials::save_claim_token(NEW_CLAIM) == ESP_OK, "new owner's BLE claim");
  check(credentials::mark_unpaired(session.claim_token) == ESP_OK, "old owner's UNPAIRED");
  reboot();
  verify_state(identity, false, NEW_CLAIM);
}

void matching_claim_is_cleared() {
  const auto identity = paired_identity();
  check(credentials::save_claim_token(OLD_CLAIM) == ESP_OK, "save session claim");
  check(credentials::mark_unpaired(OLD_CLAIM) == ESP_OK, "unpair matching claim");
  reboot();
  verify_state(identity, false, "");
}

void ble_claim_after_unpair() {
  const auto identity = paired_identity();
  check(credentials::mark_unpaired("") == ESP_OK, "unpair before BLE write");
  check(credentials::save_claim_token(NEW_CLAIM) == ESP_OK, "BLE write after unpair");
  reboot();
  verify_state(identity, false, NEW_CLAIM);
}

void failed_unpair(const std::string& failure) {
  const auto identity = paired_identity();
  check(credentials::save_claim_token(NEW_CLAIM) == ESP_OK, "save newer claim");
  const bool ambiguous = failure == "ambiguous_commit";
  if (failure == "failed_write") {
    fail_write = true;
  } else {
    fail_commit = commits + 1;
    persist_on_failure = ambiguous;
  }
  check(credentials::mark_unpaired("") != ESP_OK, "unpair storage failure must propagate");
  reboot();
  // A failed commit may or may not have persisted, but it must never erase the
  // newer claim or leave a partially changed identity.
  verify_state(identity, !ambiguous, NEW_CLAIM);
  const int written = writes, committed = commits;
  check(credentials::mark_unpaired("") == ESP_OK, "retry unpair after reboot");
  if (ambiguous) {
    check(writes == written && commits == committed, "retry rewrote committed state");
  }
  reboot();
  verify_state(identity, false, NEW_CLAIM);
}

void repeated_unpair_does_not_write() {
  const auto identity = paired_identity();
  check(credentials::save_claim_token(NEW_CLAIM) == ESP_OK, "save newer claim");
  check(credentials::mark_unpaired("") == ESP_OK, "first unpair");
  const int written = writes, committed = commits;
  check(credentials::mark_unpaired("") == ESP_OK, "duplicate unpair");
  check(writes == written && commits == committed, "duplicate unpair rewrote NVS");
  reboot();
  verify_state(identity, false, NEW_CLAIM);
}
}  // namespace

int main(int argc, char** argv) try {
  check(argc == 2, "provide exactly one regression scenario");
  const std::string scenario = argv[1];
  if (scenario == "stale_empty") delayed_unpair("");
  else if (scenario == "stale_nonempty") delayed_unpair(OLD_CLAIM);
  else if (scenario == "matching_claim") matching_claim_is_cleared();
  else if (scenario == "ble_after_unpair") ble_claim_after_unpair();
  else if (scenario == "failed_write" || scenario == "failed_commit" || scenario == "ambiguous_commit") {
    failed_unpair(scenario);
  } else if (scenario == "duplicate_unpair") repeated_unpair_does_not_write();
  else throw std::runtime_error("unknown regression scenario");
  check(handles.empty(), "NVS handle leaked");
  std::cout << "PASS " << scenario << '\n';
  return 0;
} catch (const std::exception& error) {
  std::cerr << error.what() << '\n';
  return 1;
}
