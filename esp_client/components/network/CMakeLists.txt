set(json_component json)
if(IDF_VERSION_MAJOR GREATER_EQUAL 6)
  set(json_component espressif__cjson)
endif()

idf_component_register(
  SRCS "src/protocol.cpp" "src/tls_connection.cpp" "src/wol_client.cpp"
  INCLUDE_DIRS "include"
  REQUIRES esp-tls storage
  PRIV_REQUIRES ${json_component} esp_hw_support esp_timer freertos log lwip wifi wol
)
