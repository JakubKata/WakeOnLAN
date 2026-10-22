#pragma once
#include "esp_err.h"

namespace onboarding {
// Starts once per boot: for a new unit, or after holding the setup button at power-on.
// Never erases identity or factory data. Requires initialized NVS and Wi-Fi.
esp_err_t start();
// Stop after a short grace period so the phone can read the Wi-Fi success response.
void complete();
bool in_progress();
}  // namespace onboarding
