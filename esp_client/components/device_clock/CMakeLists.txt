idf_component_register(
  SRCS "src/device_clock.cpp"
  INCLUDE_DIRS "include"
  REQUIRES esp_common
  PRIV_REQUIRES esp_netif lwip nvs_flash log freertos esp_timer
)
