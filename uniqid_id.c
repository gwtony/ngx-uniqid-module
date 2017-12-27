#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ngx_config.h>

#include "uniqid_hex.h"
#include "uniqid_id.h"

uniqid *uniqid_generate_uid(uint8_t magic, char *ip, uintptr_t time_ms, pid_t pid)
{
	int s, len = 0;
	uint8_t rand2;
	uint16_t rand;
	long int tmp;
	uniqid *id;
	char buf[UNIQID_SIZE], hbuf[UNIQID_SIZE];
	unsigned char ip_buf[sizeof(struct in_addr)];
	//long int srcrand;

	id = calloc(1, sizeof(uniqid));
	if (id == NULL) {
		return NULL;
	}

	s = inet_pton(AF_INET, ip, ip_buf);
	if (s != 1) {
		free(id);
		return NULL;
	}

	tmp = ngx_random();
	rand = (uint16_t)(tmp % 65536);
	rand2 = (uint8_t)(tmp % 255);

	memset(buf, 0, UNIQID_SIZE);

	buf[0] = magic;
	len++;
	memcpy(buf + len, ip_buf, 4);
	len += 4;
	memcpy(buf + len, (uint8_t*)&time_ms, sizeof(uintptr_t) - 2);
	len += sizeof(uintptr_t) - 2; //drop high 16bit, use low 48bit
	memcpy(buf + len, (uint8_t *)&pid, 2); //use low 16bit
	len += 2;
	memcpy(buf + len, (uint8_t *)&rand, 2);
	len += 2;
	memcpy(buf + len, (uint8_t *)&rand2, 1);
	len++;
	//len set to UNIQID_SIZE/2

	memset(hbuf, 0, sizeof(uniqid));
	encode_to_hex(hbuf, (uint8_t *)buf, len);
	memcpy(id, hbuf, sizeof(uniqid));

	return id;
}

