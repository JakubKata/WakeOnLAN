#pragma once

namespace updates {
void start();
// A new image is healthy only after Wi-Fi, TLS validation and cloud authentication.
void cloud_ready();
}  // namespace updates
