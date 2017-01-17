#ifndef UNIQID_ZIP_H
#define UNIQID_ZIP_H
//#include <stdio.h>
#include <string.h>
#include <zlib.h>

#define UNIQID_ZIP_CHUNK 4096

int uniqid_zip(char *in, size_t size, char *out);
int uniqid_unzip(char *in, size_t size, char *out);

#endif
