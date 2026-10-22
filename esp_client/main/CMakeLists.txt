idf_component_register(
  SRCS "main.cpp"
  INCLUDE_DIRS "."
  PRIV_REQUIRES network storage wifi onboarding nvs_flash freertos updates
)
