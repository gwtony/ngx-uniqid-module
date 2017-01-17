#ifndef UNIQID_ID_H
#define UNIQID_ID_H
#include <stdint.h>
#include <unistd.h>

//TODO: set in config
#define UNIQID_MAGIC 0x01

/* 32byte UNIQID in hex code: 
 * magic   1 byte
 * ip      4 byte
 * timems  6 byte(drop high 2 byte)
 * pid     2 byte
 * rand5   2 byte
 * padding 2 byte
 * */
#define UNIQID_SIZE 32

typedef uint8_t uniqid[UNIQID_SIZE];

uniqid *uniqid_generate_uid(uint8_t magic, char *ip, uintptr_t time_ms, pid_t pid);

#endif
