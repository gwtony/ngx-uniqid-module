#include "uniqid_msgpack.h"
#include "uniqid_udp.h"

uniqid_msgpack_ctx *uniqid_msgpack_ctx_init()
{
	uniqid_msgpack_ctx *mctx;
	mctx = malloc(sizeof(uniqid_msgpack_ctx));
	if (mctx == NULL) {
		return NULL;
	}
	//msgpack_unpacked_init(&mctx->unpacked);
	//msgpack_sbuffer_init(&mctx->sbuffer);

	return mctx;
}

void uniqid_msgpack_ctx_destroy(uniqid_msgpack_ctx *mctx)
{
	//msgpack_unpacked_destroy(&mctx->unpacked);
	//msgpack_sbuffer_destroy(&mctx->sbuffer);
	free(mctx);
}

void uniqid_init_msgpack_buffer(uniqid_msgpack_ctx *mctx)
{
	msgpack_sbuffer_init(&mctx->sbuffer);
}
void uniqid_destroy_msgpack_buffer(uniqid_msgpack_ctx *mctx)
{
	msgpack_sbuffer_destroy(&mctx->sbuffer);
}

//void uniqid_address_to_msgpack(msgpack_packer *&pk, char *pip, uint16_t pport, char *lip, uint16_t lport)
//{
//
//}
//void uniqid_data_to_msgpack(msgpack_packer *&pk, char *data, int len)
//{
//}

int uniqid_generate_msgpack(uniqid_msgpack_ctx *mctx, char *uid, char *puid, char *pip, uint16_t pport, char *lip, uint16_t lport, char *data, int len)
{
	uint8_t *mdata;
	msgpack_packer pk;

	msgpack_sbuffer_init(&mctx->sbuffer);
	msgpack_packer_init(&pk, &mctx->sbuffer, msgpack_sbuffer_write);

	if (puid) {
		msgpack_pack_map(&pk, 8);
	} else {
		msgpack_pack_map(&pk, 7);
	}
	msgpack_pack_str(&pk, strlen("Uid"));
	msgpack_pack_str_body(&pk, "Uid", strlen("Uid"));
	msgpack_pack_str(&pk, strlen(uid));
	msgpack_pack_str_body(&pk, uid, strlen(uid));

	if (puid) {
		msgpack_pack_str(&pk, strlen("Puid"));
		msgpack_pack_str_body(&pk, "Puid", strlen("Puid"));
		msgpack_pack_str(&pk, strlen(puid));
		msgpack_pack_str_body(&pk, puid, strlen(puid));
	}
	msgpack_pack_str(&pk, strlen("Pip"));
	msgpack_pack_str_body(&pk, "Pip", strlen("Pip"));
	msgpack_pack_str(&pk, strlen(pip));
	msgpack_pack_str_body(&pk, pip, strlen(pip));

	msgpack_pack_str(&pk, strlen("Pport"));
	msgpack_pack_str_body(&pk, "Pport", strlen("Pport"));
	msgpack_pack_uint16(&pk, pport);
	
	msgpack_pack_str(&pk, strlen("Lip"));
	msgpack_pack_str_body(&pk, "Lip", strlen("Lip"));
	msgpack_pack_str(&pk, strlen(lip));
	msgpack_pack_str_body(&pk, lip, strlen(lip));

	msgpack_pack_str(&pk, strlen("Lport"));
	msgpack_pack_str_body(&pk, "Lport", strlen("Lport"));
	msgpack_pack_uint16(&pk, lport);

	msgpack_pack_str(&pk, strlen("Dlen"));
	msgpack_pack_str_body(&pk, "Dlen", strlen("Dlen"));
	msgpack_pack_uint16(&pk, len);

	msgpack_pack_str(&pk, strlen("Data"));
	msgpack_pack_str_body(&pk, "Data", strlen("Data"));
	msgpack_pack_str(&pk, len);
	msgpack_pack_str_body(&pk, data, len);

	//msgpack_packer_free(&pk);

	return 0;
}

char *uniqid_get_msgpack_data(uniqid_msgpack_ctx *mctx)
{
	return mctx->sbuffer.data;
}

int uniqid_get_msgpack_size(uniqid_msgpack_ctx *mctx)
{
	return mctx->sbuffer.size;
}
