#pragma once
#include <cstddef>
int mbedtls_sha256(const unsigned char* input, size_t length, unsigned char* output, int is224);
