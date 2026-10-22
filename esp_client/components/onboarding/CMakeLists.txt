idf_component_register(
  SRCS "src/onboarding.cpp"
  INCLUDE_DIRS "include"
  REQUIRES esp_common
  PRIV_REQUIRES wifi_provisioning protocomm nvs_flash esp_event esp_wifi esp_driver_gpio
                storage device_clock wifi json freertos log
)
