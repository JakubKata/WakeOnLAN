idf_component_register(
  SRCS "src/updates.cpp"
  INCLUDE_DIRS "include"
  PRIV_REQUIRES app_update esp_http_client esp-tls mbedtls esp_app_format
                esp_system esp_timer esp_hw_support efuse freertos log wifi device_clock onboarding
)
