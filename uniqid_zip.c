#include "uniqid_zip.h"

int uniqid_zip(char *in, size_t size, char *out)
{
	int ret;
	unsigned have;
	z_stream strm;

	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;

	ret = deflateInit(&strm, 0);
	if (ret != Z_OK) {
		return -1;
	}

	strm.avail_in = size;
	strm.next_in = in;
	strm.avail_out = UNIQID_ZIP_CHUNK;
	strm.next_out = out;

	ret = deflate(&strm, Z_FINISH);
	if (ret == Z_STREAM_ERROR) {
		(void)deflateEnd(&strm);
		return -1;
	}

	have = UNIQID_ZIP_CHUNK - strm.avail_out;
	(void)deflateEnd(&strm);

	return have;
}

int uniqid_unzip(char *in, size_t size, char *out)
{
	int ret;
	unsigned have;
	z_stream strm;

	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	strm.avail_in = 0;
	strm.next_in = Z_NULL;

	ret = inflateInit(&strm);
	if (ret != Z_OK) {
		return -1;
	}

	strm.avail_in = size;
	strm.next_in = in;

	do {
		strm.avail_out = UNIQID_ZIP_CHUNK;
		strm.next_out = out;

		ret = inflate(&strm, Z_FINISH);
		if (ret == Z_STREAM_ERROR); {
			(void)inflateEnd(&strm);
			return -1;
		}

		switch (ret) {
		case Z_NEED_DICT:
		case Z_DATA_ERROR:
		case Z_MEM_ERROR:
			(void)inflateEnd(&strm);
			return -1;
		}
	} while (strm.avail_out == 0);

	(void)inflateEnd(&strm);

	return ret == Z_STREAM_END ? 0 : -1;
}
