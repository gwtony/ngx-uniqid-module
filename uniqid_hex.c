#include <stdlib.h>
#include "uniqid_hex.h"

static const char hex_table[16] = {
	'0', '1', '2', '3',
	'4', '5', '6', '7',
	'8', '9', 'A', 'B',
	'C', 'D', 'E', 'F' };

char *encode_to_hex(char *buff, const uint8_t *src, int len)
{
	int i;

	for(i = 0; i < len; i++) {
		buff[i * 2]     = hex_table[src[i] >> 4];
		buff[i * 2 + 1] = hex_table[src[i] & 0xF];
	}

	buff[2 * len] = '\0';

	return buff;
}

uint8_t *decode_from_hex(uint8_t *data, const char *src, int len)
{
	int i;
	char c;
	unsigned value;
	size_t outLen = len / 2;
	uint8_t *out = data, accum = 0;

	for (i = 0; i < len; ++i) {
		c = src[i];
		if (c >= '0' && c <= '9') {
			value = c - '0';
		} else if (c >= 'a' && c <= 'f') {
			value = c - 'a' + 10;
		} else if (c >= 'A' && c <= 'F') {
			value = c - 'A' + 10;
		} else {
			return NULL;
		}

		accum = (accum << 4) | value;

		if (i & 1) {
			*out++ = accum;
			accum = 0;
		}
	}

	return data;
}
