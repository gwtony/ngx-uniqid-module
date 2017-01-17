//#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
//#include <ngx_core.h>
#include <sys/socket.h>
#include <ngx_config.h>

#include "uniqid_id.h"

uniqid *uniqid_generate_uid(uint8_t magic, char *ip, uintptr_t time_ms, pid_t pid)
{
	int domain, s, len = 0;
	uint16_t rand;
	uniqid *id;
	char buf[UNIQID_SIZE], hbuf[UNIQID_SIZE];
	unsigned char ip_buf[sizeof(struct in_addr)];
	long int srcrand;

	id = calloc(1, sizeof(uniqid));
	if (id == NULL) {
		return NULL;
	}

	s = inet_pton(AF_INET, ip, ip_buf);
	if (s != 1) {
		free(id);
		return NULL;
	}

	//srand((unsigned)time(NULL));
	//srcrand = random();
	//fprintf(stderr, "random is %ld\n", srcrand);
	
	rand = (uint16_t)ngx_random();

	fprintf(stderr, "generate uid rand is %u\n", rand);

	memset(buf, 0, UNIQID_SIZE);

	buf[0] = magic;
	len++;
	memcpy(buf + len, ip_buf, 4);
	len += 4;
	memcpy(buf + len, (uint8_t*)&time_ms, sizeof(uintptr_t) - 2);
	len += sizeof(uintptr_t) - 2; //drop high 16bit
	memcpy(buf + len, (uint8_t *)&pid, 2);
	len += 2;
	memcpy(buf + len, (uint8_t *)&rand, 2);
	len += 2;
	//len set to UNIQID_SIZE/2
	len++;

	memset(hbuf, 0, sizeof(uniqid));
	encode_to_hex(hbuf, buf, len);
	memcpy(id, hbuf, sizeof(uniqid));

	return id;
}

