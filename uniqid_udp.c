#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "uniqid_udp.h"
#include "uniqid_hex.h"
#include <arpa/inet.h>

uniqid_udp_data *uniqid_generate_data(uniqid *uid, uint16_t dlen, uint8_t *data)
{
	int ret;
	uniqid_udp_data *udata;
	char buf[INET_ADDRSTRLEN];

	udata = malloc(sizeof(uniqid_udp_data) + dlen);
	if (udata == NULL) {
		return NULL;
	}

	memset(udata, 0, sizeof(uniqid_udp_data) + dlen);

	memcpy(udata->key, uid, UNIQID_SIZE);
	udata->vlen = dlen;
	memcpy(udata->value, data, dlen);
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
	//struct sockaddr_in *addr;

	//addr = calloc(1, sizeof(struct sockaddr_in));
	//if (addr == NULL) {
	//	return NULL;
	//}

	addr->sin_family = AF_INET;
	inet_pton(AF_INET, ip, &addr->sin_addr);
	addr->sin_port = htons(port);

	return 0;
}
