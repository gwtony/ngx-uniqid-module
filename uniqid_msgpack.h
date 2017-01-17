#ifndef UNIQID_MSGPACK_H
#define UNIQID_MSGPACK_H
#include <msgpack.h>

typedef struct {
	char uid[88];
	char puid[88];
	char pip[16];
	uint16_t pport;
	char lip[16];
	uint16_t lport;
	uint16_t dlen;
	char data[0];
} uniqid_msgpack_data;

typedef struct {
	msgpack_unpacked unpacked;
	msgpack_sbuffer sbuffer;
} uniqid_msgpack_ctx;

uniqid_msgpack_ctx *uniqid_msgpack_ctx_init();
void uniqid_msgpack_ctx_destroy(uniqid_msgpack_ctx *mpctx);
void uniqid_init_msgpack(uniqid_msgpack_ctx *mctx);
void uniqid_destroy_msgpack(uniqid_msgpack_ctx *mctx);
//int uniqid_data_to_msgpack(uniqid_msgpack_ctx *ctx, char *data, int len);
int uniqid_generate_msgpack(uniqid_msgpack_ctx *mctx, char *uid, char *puid, char *pip, uint16_t pport, char *lip, uint16_t lport, char *data, int len);
char *uniqid_get_msgpack_data(uniqid_msgpack_ctx *ctx);
int uniqid_get_msgpack_size(uniqid_msgpack_ctx *ctx);

#endif
