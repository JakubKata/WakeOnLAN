idf_component_register(
  SRCS "src/magic_packet.cpp"
  INCLUDE_DIRS "include"
  REQUIRES esp_common
  PRIV_REQUIRES esp_netif lwip log freertos
)
