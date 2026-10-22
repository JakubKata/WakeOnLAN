idf_component_register(
  SRCS "src/protocol.cpp" "src/tls_connection.cpp" "src/wol_client.cpp"
  INCLUDE_DIRS "include"
  REQUIRES esp-tls storage
  PRIV_REQUIRES json esp_hw_support esp_timer freertos log lwip wifi wol device_clock mbedtls onboarding updates
)
