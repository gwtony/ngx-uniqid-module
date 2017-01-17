#ifndef UNIQID_HEX_H
#define UNIQID_HEX_H
#include <stdint.h>

char *encode_to_hex(char *buff, const uint8_t *src, int len);
uint8_t *decode_from_hex(uint8_t *data, const char *src, int len);

#endif

