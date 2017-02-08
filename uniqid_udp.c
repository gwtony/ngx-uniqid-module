#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "uniqid_udp.h"
#include "uniqid_hex.h"

uniqid_udp_data *uniqid_generate_data(uniqid *uid, uniqid *puid, char *pip, uint16_t pport, char *lip, uint16_t lport, uint16_t dlen, uint8_t *data)
{
	int ret;
	uniqid_udp_data *udata;
	char buf[INET_ADDRSTRLEN];

	udata = malloc(sizeof(uniqid_udp_data) + dlen);
	if (udata == NULL) {
		fprintf(stderr, "generate data malloc failed\n");
		return NULL;
	}
	memset(udata, 0, sizeof(uniqid_udp_data) + dlen);

	memcpy(udata, uid, UNIQID_SIZE);
	if (puid) {
		memcpy(udata->puid, puid, UNIQID_SIZE);
	}

	memset(buf, 0, INET_ADDRSTRLEN);
	ret = inet_pton(AF_INET, pip, buf);
	if (ret <= 0) {
		free(udata);
		fprintf(stderr, "pton pip failed\n");
		return NULL;
	}
	memcpy(udata->pip, buf, 4);
	udata->pport = htons(pport);
	ret = inet_pton(AF_INET, lip, buf);
	if (ret <= 0) {
		free(udata);
		fprintf(stderr, "pton lip failed\n");
		return NULL;
	}
	memcpy(udata->lip, buf, 4);
	udata->lport = htons(lport);
	udata->dlen = htons(dlen);
	memcpy(udata->data, data, dlen);

	return udata;
}

int uniqid_udp_send(int sd, void *data, int len, struct sockaddr_in *addr)
{
	return sendto(sd, data, len, MSG_DONTWAIT, (struct sockaddr *)addr, sizeof(struct sockaddr));
}

int uniqid_udp_socket()
{
	int fd;
	int ret, val = 1;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		return -1;
	}
	
	ret = setsockopt(fd, SOL_SOCKET, SO_BROADCAST | SO_REUSEADDR, &val, sizeof(int));
	if (ret < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

int uniqid_udp_addr(char *ip, uint16_t port, struct sockaddr_in *addr)
{
	addr->sin_family = AF_INET;
	inet_pton(AF_INET, ip, &addr->sin_addr);
	addr->sin_port = htons(port);

	return 0;
}
