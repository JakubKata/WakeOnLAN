idf_component_register(
  SRCS "src/wifi.cpp"
  INCLUDE_DIRS "include"
  REQUIRES esp_common freertos
  PRIV_REQUIRES esp_wifi esp_netif esp_event log
)
