idf_component_register(
  SRCS "src/credentials.cpp"
  INCLUDE_DIRS "include"
  REQUIRES esp_common
  PRIV_REQUIRES nvs_flash esp_hw_support mbedtls
)
