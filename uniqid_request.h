#ifndef UNIQID_REQUEST_H
#define UNIQID_REQUEST_H
#include <ngx_http.h>
#include "uniqid_id.h"

int get_local_ip(char *buf);

pid_t uniqid_request_get_pid();

uint64_t uniqid_request_get_timems();

uniqid *uniqid_request_generate_uid(char *ip);
uniqid *uniqid_request_get_uid(ngx_http_request_t *r);

int ngx_http_replace_header(ngx_str_t *key, ngx_str_t *value, ngx_http_request_t *r);

char *uniqid_request_get_localip(ngx_http_request_t *r);
uint16_t uniqid_request_get_localport(ngx_http_request_t *r);

char *uniqid_request_get_peerip(ngx_http_request_t *r);
uint16_t uniqid_request_get_peerport(ngx_http_request_t *r);

ngx_str_t ngx_http_uniqid_get_rawheader(ngx_http_request_t *r);

uint16_t uniqid_request_uid_hash(uniqid *id, int len);

#endif
