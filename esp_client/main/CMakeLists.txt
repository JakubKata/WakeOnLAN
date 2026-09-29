set(server_cert "${CMAKE_CURRENT_LIST_DIR}/certs/server.crt")
if(NOT EXISTS "${server_cert}")
  message(FATAL_ERROR "Missing ${server_cert}: copy the server TLS certificate (server/server.crt) there.")
endif()

idf_component_register(
  SRCS "main.cpp"
  INCLUDE_DIRS "."
  PRIV_REQUIRES console network storage wifi nvs_flash freertos
  EMBED_TXTFILES "certs/server.crt"
)
