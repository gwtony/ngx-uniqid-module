#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sys/time.h>

#include "uniqid_zip.h"
#include "uniqid_udp.h"
#include "uniqid_request.h"
#include "uniqid_id.h"
#include "uniqid_msgpack.h"

#define DEFAULT_USERVER_NUM 10

static void *ngx_http_uniqid_srv_create_conf(ngx_conf_t *cf);
static char *ngx_http_uniqid_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_uniqid_preconf(ngx_conf_t *cf);
static ngx_int_t uniqid_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_uniqid_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_uniqid_done(ngx_http_request_t *r, void *data, ngx_int_t rc);
static char *ngx_http_uniqid_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t uniqid_get(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static ngx_command_t ngx_http_uniqid_commands[] = {
    { ngx_string("uniqid_pass"),
	  NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_uniqid_pass,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};

static ngx_http_variable_t uniqid_variables[] = {
    { ngx_string("uniqid_result"),
        NULL, uniqid_get,
        0,
        0,
        0
    },
    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

typedef struct {
	int sd;
	ngx_str_t usip;
	uint16_t  usport;
	struct sockaddr_in addr;
} userver_t;

typedef struct {
	int off;
	//int sd;
	//char usip[16];
	//ngx_str_t usip;
	//uint16_t  usport;
	userver_t *uservers;
	int userver_len;

	char local_ip[16];
	//struct sockaddr_in *addr;
	uniqid_msgpack_ctx *mctx;
} ngx_http_uniqid_conf_t; 

typedef struct {
	ngx_str_t result;
	ngx_int_t done;
} ngx_http_uniqid_ctx_t;

static ngx_http_module_t  ngx_http_uniqid_module_ctx = {
    ngx_http_uniqid_preconf,       /* preconfiguration */
    ngx_http_uniqid_init,          /* postconfiguration */

    NULL,                        /* create main configuration */
    NULL,                        /* init main configuration */

    ngx_http_uniqid_srv_create_conf, /* create server configuration */
    NULL,                        /* merge server configuration */

    //ngx_http_uniqid_create_conf,   /* create location configuration */
	NULL,
	NULL
    //ngx_http_uniqid_merge_conf     /* merge location configuration */
};


ngx_module_t  ngx_http_uniqid_module = {
    NGX_MODULE_V1,
    &ngx_http_uniqid_module_ctx,    /* module context */
    ngx_http_uniqid_commands,       /* module directives */
    NGX_HTTP_MODULE,              /* module type */
    NULL,                         /* init master */
    NULL,                         /* init module */
    NULL,                         /* init process */
    NULL,                         /* init thread */
    NULL,                         /* exit thread */
    NULL,                         /* exit process */
	NULL,                         /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_uniqid_preconf(ngx_conf_t *cf)
{
	if (uniqid_add_variables(cf) == NGX_OK) {
		return NGX_OK;
	}
	return NGX_ERROR;
}

static ngx_int_t uniqid_add_variables(ngx_conf_t *cf)
{
	int i;
	ngx_http_variable_t *var;

	for (i=0; uniqid_variables[i].name.len>0; ++i) {
		var = ngx_http_add_variable(cf, &uniqid_variables[i].name, uniqid_variables[i].flags);
		if (var==NULL) {
			ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "uniqid add variable '%s' failed.", uniqid_variables[i].name.data);

			return NGX_ERROR;
		}

		var->set_handler = uniqid_variables[i].set_handler;
		var->get_handler = uniqid_variables[i].get_handler;
		var->data = uniqid_variables[i].data;
	}

	return NGX_OK;
}

static ngx_int_t
ngx_http_uniqid_handler(ngx_http_request_t *r)
{
    ngx_table_elt_t               *h, *ho;
    ngx_http_uniqid_ctx_t   *ctx;
    ngx_http_uniqid_conf_t  *uscf;
	ngx_list_part_t       *part;
	ngx_table_elt_t       *header;

	pid_t pid;
	char *data;
	int size, ret;
	ngx_str_t raw;
	char *pip, *lip, *header_zipped;
	uint64_t time_ms;
	uniqid_udp_data *udata;
	uniqid *uid, *puid;
	uint16_t pport, lport;
	struct timeval begin, end;
	ngx_str_t key = ngx_string("Uniqid"), value;

	int i;
	//msgpack_zone mempool;
	//uniqid_msgpack_data umd;
	//msgpack_object deserialized;

	//gettimeofday(&begin, NULL);
	uscf = ngx_http_get_module_srv_conf(r, ngx_http_uniqid_module);

    if (uscf->off == 1) {
        return NGX_DECLINED;
    }

	if (r->internal) {
		return NGX_DECLINED;
	}
	ctx = ngx_http_get_module_ctx(r, ngx_http_uniqid_module);
	if (ctx == NULL) {
		ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_uniqid_ctx_t));
		if (ctx == NULL) {
			return NGX_ERROR;
		}
	}
	if (ctx->done) {
        return NGX_DECLINED;
	}

	//gettimeofday(&begin, NULL);
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "uniqid handler");

	pid = uniqid_request_get_pid();
	time_ms = uniqid_request_get_timems();
	uid = uniqid_request_generate_uid(uscf->local_ip);
	puid = uniqid_request_get_uid(r);
	pip = uniqid_request_get_peerip(r);
	pport = uniqid_request_get_peerport(r);
	lip = uscf->local_ip;
	lport = uniqid_request_get_localport(r);
	
	raw = ngx_http_uniqid_get_rawheader(r);

    header_zipped = ngx_pcalloc(r->pool, raw.len);
	ret = uniqid_zip(raw.data, raw.len, header_zipped);
	if (ret < 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "uniqid zip failed");
		return NGX_DECLINED;
	}
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "uniqid data zipped from %d to %d", raw.len, ret);

	ret = uniqid_generate_msgpack(uscf->mctx, (char *)uid, (char *)puid, pip, pport, lip, lport, header_zipped, ret);
	if (ret < 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "uniqid encode data to msgpack failed");
		return NGX_DECLINED;
	}
	//free(uid);

	data = uniqid_get_msgpack_data(uscf->mctx);
	size = uniqid_get_msgpack_size(uscf->mctx);
	

	//debug
	//msgpack_zone_init(&mempool, 2048);
	//ret = msgpack_unpack(data, size, NULL, &mempool, &deserialized);
	//msgpack_object_print(stderr, deserialized);

	udata = uniqid_generate_data(uid, size, data);
	size += UNIQID_DATA_SIZE;

	//TODO: uid 
	i = uniqid_request_uid_hash(uid, uscf->userver_len);
	//ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "i is %d", i);
	fprintf(stderr, "i is %d\n", i);
	//i = 0;
	ret = uniqid_udp_send(uscf->uservers[i].sd, udata, size, &uscf->uservers[i].addr);
	if (ret < size) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "uniqid udp send failed: %d", ret);
	} else {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "uniqid udp send success: %d", ret);
	}

	uniqid_destroy_msgpack_buffer(uscf->mctx);
	
	free(udata);
	ctx->done = 1;
	ngx_http_set_ctx(r, ctx, ngx_http_uniqid_module);
	
	gettimeofday(&end, NULL);
	
	if (puid) {
		value.len = UNIQID_SIZE;
		value.data = (void *)uid;
		ngx_http_replace_header(&key, &value, r);
	} else {
		h = ngx_list_push(&r->headers_in.headers);
		if (h == NULL) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		h->key.data = ngx_pnalloc(r->pool, key.len + 1);
		ngx_memcpy(h->key.data, key.data, key.len);
		h->key.len = key.len;
		h->key.data[h->key.len] = '\0';

		h->value.data = ngx_pnalloc(r->pool, 32 + 1);
		ngx_memcpy(h->value.data, uid, 32);
		h->value.len = 32;
		h->value.data[h->value.len] = '\0';

		h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
		if (h->lowcase_key == NULL) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
		h->hash = ngx_hash_key(h->key.data, h->key.len);
	}

	free(uid);
	//ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "cost %d us", (end.tv_usec-begin.tv_usec < 0)? 1000000 + end.tv_usec-begin.tv_usec : (end.tv_usec-begin.tv_usec));

	return NGX_DECLINED;
}

static void *
ngx_http_uniqid_srv_create_conf(ngx_conf_t *cf)
{
    ngx_http_uniqid_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_uniqid_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
	if (get_local_ip(conf->local_ip) < 0) {
		ngx_log_error(NGX_LOG_ERR, cf->log, 0, "init uniqid local ip from eth0 failed");
		return NGX_CONF_ERROR;
	}
	

	conf->off = 1;
	//conf->uservers = ngx_pcalloc(cf->pool, sizeof(userver_t) * DEFAULT_USERVER_NUM);
	//if (conf->uservers == NULL) {
	//	return NGX_CONF_ERROR;
	//}

	//conf->sd = uniqid_udp_socket();
	//if (conf->sd < 0) {
	//	ngx_log_error(NGX_LOG_ERR, cf->log, 0, "init uniqid socket failed");
	//	return NGX_CONF_ERROR;
	//}
	//conf->usip.data = NULL;
	//conf->usip.len = 0;
	conf->mctx = uniqid_msgpack_ctx_init();
	if (conf->mctx == NULL) {
		ngx_log_error(NGX_LOG_ERR, cf->log, 0, "init uniqid msgpack ctx failed");
		return NGX_CONF_ERROR;
	}

    return conf;
}

//static char *
//ngx_http_uniqid_merge_conf(ngx_conf_t *cf, void *parent, void *child)
//{
//    ngx_http_uniqid_conf_t *prev = parent;
//    ngx_http_uniqid_conf_t *conf = child;
//
//	ngx_conf_merge_str_value(conf->usip, prev->usip, "");
//	conf->usport = prev->usprot;
//
//    return NGX_CONF_OK;
//}

static ngx_int_t
ngx_http_uniqid_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	*h = ngx_http_uniqid_handler;
	

    return NGX_OK;
}

static char *
ngx_http_uniqid_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	int 				  i, len, uspos = 0;
	char *pos, *cur, *sep, ip[32];
    ngx_str_t            *value;
	userver_t *us;
    ngx_http_uniqid_conf_t *uscf = conf;

    if (uscf->userver_len != 0) {
        return "is duplicate";
    }

    value = cf->args->elts;

	for (i = 1; i < cf->args->nelts; i++) {
		if (ngx_strncmp(value[i].data, "uniqid://", 9) == 0) {
			uscf->off = 0;
			cur = value[i].data + 9;
			len = 1;

			sep = cur;
			while (sep = strchr(sep, ',')) {
				len++;
				sep = sep + 1;
			}
			uscf->userver_len = len;
			uscf->uservers = (userver_t *)ngx_pcalloc(cf->pool, sizeof(userver_t) * len);
			if (uscf->uservers == NULL) {
				return NGX_CONF_ERROR;
			}

			while (sep = strchr(cur, ',')) {
				if ((pos = strchr(cur, ':')) == NULL) {
					return "no port in uniqid address";
				}
				len = pos - cur;
				if (len >= 16) {
					return "ip is too long";
				}

				us = &uscf->uservers[uspos];
				us->usip.data = cur;
				us->usip.len = len;
				us->usport = ngx_atoi(pos + 1, sep - pos - 1);
				if (us->usport <= 0 || us->usport > 65535) {
					return "invalid port in uniqid address";
				}
				memcpy(ip, us->usip.data, us->usip.len);
				ip[us->usip.len] = 0;
				uniqid_udp_addr(ip, us->usport, &us->addr);

				us->sd = uniqid_udp_socket();
				if (us->sd < 0) {
					return "init uniqid socket failed";
				}

				uspos++;
				cur = sep + 1;
			}

			if ((pos = strchr(cur, ':')) == NULL) {
				return "no port in uniqid address";
			}
			len = pos - cur;
			if (len >= 16) {
				return "ip is too long";
			}
			us = &uscf->uservers[uspos];
			us->usip.data = cur;
			us->usip.len = len;
			us->usport = ngx_atoi(pos + 1, value[i].len - ((u_char *)pos + 1 - value[i].data));
			if (us->usport <= 0 || us->usport > 65535) {
				return "invalid port in uniqid address";
			}
			memcpy(ip, us->usip.data, us->usip.len);
			ip[us->usip.len] = 0;
			uniqid_udp_addr(ip, us->usport, &us->addr);
			us->sd = uniqid_udp_socket();
			if (us->sd < 0) {
				return "init uniqid socket failed";
			}

			continue;
		}
	}

	return NGX_CONF_OK;
}

static ngx_int_t uniqid_get(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
	ngx_http_uniqid_ctx_t *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_uniqid_module);

    if (ctx != NULL) {
        //if (ctx->done) {
		v->valid = 1;
		v->no_cacheable = 0;
		v->not_found = 0;
		v->data = (void*)ctx->result.data;
		v->len = ctx->result.len;
		return NGX_OK;
		//}
	}
	v->valid = 0;
	v->no_cacheable = 0;
	v->not_found = 1;
	v->data = NULL;
	v->len = 0;
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "uniqid result not found");
	return NGX_ERROR;
}
