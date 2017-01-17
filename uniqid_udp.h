#ifndef UNIQID_H
#define UNIQID_H
#include <stdint.h>
#include "uniqid_id.h"

//typedef struct {
//	uniqid key;
//	uint16_t vlen;
//	uint8_t value[0];
//} uniqid_udp_data;

typedef struct {
	uniqid uid;
	uniqid puid;
	uint8_t pip[4];
	uint16_t pport;
	uint8_t lip[4];
	uint16_t lport;
	uint16_t dlen;
	uint8_t data[0];
} uniqid_udp_data;

#define UNIQID_DATA_SIZE sizeof(uniqid_udp_data)

uniqid_udp_data *uniqid_generate_data(uniqid *uid, uniqid *puid, char *pip, uint16_t pport, char *lip, uint16_t lport, uint16_t dlen, uint8_t *data);

int uniqid_udp_socket();
int uniqid_udp_addr(char *ip, uint16_t port, struct sockaddr_in *addr);
int uniqid_udp_send(int sd, void *data, int len, struct sockaddr_in *addr);

#endif
