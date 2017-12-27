#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sys/time.h>

#include "uniqid_udp.h"
#include "uniqid_request.h"
#include "uniqid_id.h"

#define MAX_HEADER_SIZE 65536

static void *ngx_http_uniqid_srv_create_conf(ngx_conf_t *cf);
//static char *ngx_http_uniqid_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_uniqid_preconf(ngx_conf_t *cf);
static ngx_int_t uniqid_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_uniqid_init(ngx_conf_t *cf);
//static ngx_int_t ngx_http_uniqid_done(ngx_http_request_t *r, void *data, ngx_int_t rc);
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
    { ngx_string("uniqid_id"),
        NULL, uniqid_get,
        0,
        0,
        0
    },
    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

typedef struct {
	int off;
	int id_only;
	int sd;
	struct sockaddr_un addr;
	ngx_str_t socket_path;

	char local_ip[16];
} ngx_http_uniqid_conf_t; 

typedef struct {
	char result[UNIQID_SIZE];
	ngx_int_t done;
} ngx_http_uniqid_ctx_t;

char uniqid_local_ip[16];
int local_ip_init = 0;

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
    ngx_table_elt_t         *h;
    ngx_http_uniqid_ctx_t   *ctx;
    ngx_http_uniqid_conf_t  *uscf;

	//pid_t pid;
	int size, ret;
	ngx_str_t raw;
	char *pip, *lip;
	uint64_t time_ms;
	uniqid_udp_data *udata;
	uniqid *uid, *puid;
	uint16_t pport, lport;
	ngx_str_t key = ngx_string("Uniqid"), value;

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

	//pid = uniqid_request_get_pid();
	time_ms = uniqid_request_get_timems();

	uid = uniqid_request_generate_uid(uscf->local_ip);
	if (uid == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "uniqid generate uniqid failed");
		return NGX_DECLINED;
	}

	puid = uniqid_request_get_uid(r);
	if (uscf->id_only) {
		goto id_only;
	}
	pip = uniqid_request_get_peerip(r);
	pport = uniqid_request_get_peerport(r);
	lip = uscf->local_ip;
	lport = uniqid_request_get_localport(r);
	
	//ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "uniqid pport is %d, lport is %d", pport, lport);
	
	raw = ngx_http_uniqid_get_rawheader(r);
	if (raw.len > MAX_HEADER_SIZE) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "uniqid ignore too big header");
		return NGX_DECLINED;
	}

	udata = uniqid_generate_data(uid, puid, pip, pport, lip, lport, raw.len, raw.data);
	size = UNIQID_DATA_SIZE + raw.len;

	ret = sendto(uscf->sd, udata, size, MSG_DONTWAIT, (struct sockaddr *)&uscf->addr, sizeof(struct sockaddr_un));
	if (ret < size) {
		if ((time_ms % 100) == 0) {
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "uniqid send to unix socket failed: %d(%d)[%d], %s", ret, errno, EFAULT, strerror(errno));
		}
	}

	free(udata);

id_only:
	ctx->done = 1;
	strncpy(ctx->result, (const char *)uid, UNIQID_SIZE);

	ngx_http_set_ctx(r, ctx, ngx_http_uniqid_module);
	
	//gettimeofday(&end, NULL);
	
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
        return NULL;
    }

	if (local_ip_init == 0) {
		if (get_local_ip(uniqid_local_ip) < 0) {
			ngx_log_error(NGX_LOG_ERR, cf->log, 0, "init uniqid local ip from hostname failed");
			return NULL;
		}
		local_ip_init = 1;
	}
	memcpy(conf->local_ip, uniqid_local_ip, 16);
	conf->off = 1;
	conf->id_only = 0;
	conf->socket_path.len = 0;
	conf->sd = -1;
	memset(&conf->addr, 0, sizeof(conf->addr));

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
	unsigned int i;
	//int ret;
	//int bufsize = 100000;
	//char *pos, *cur, *sep, ip[32];
    ngx_str_t    *value;
	char path[1024];
	//userver_t *us;
    ngx_http_uniqid_conf_t *uscf = conf;

    if (uscf->socket_path.len != 0) {
        return "is duplicate";
    }
	if (uscf->off == 0) {
		return "is duplicate";
	}

    value = cf->args->elts;

	for (i = 1; i < cf->args->nelts; i++) {
		if (ngx_strncmp(value[i].data, "/", 1) == 0) {
			uscf->off = 0;
			uscf->socket_path.data = value[i].data;
			uscf->socket_path.len = value[i].len;
			memset(path, 0, 1024);
			memcpy(path, value[i].data, value[i].len);

			uscf->sd = socket(AF_UNIX, SOCK_DGRAM, 0);
			if (uscf->sd < 0) {
				return NGX_CONF_ERROR;
			}
			//ret = setsockopt(uscf->sd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
			//if (ret < 0) {
			//	return NGX_CONF_ERROR;
			//}

			uscf->addr.sun_family = AF_UNIX;
			strncpy(uscf->addr.sun_path, path, sizeof(uscf->addr.sun_path));

			continue;
		} else if (ngx_strncmp(value[i].data, "off", 3) == 0) {
			uscf->off = 0;
			uscf->id_only = 1;
			continue;
		}
	}


	return NGX_CONF_OK;
}

static ngx_int_t uniqid_get(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
	ngx_http_uniqid_ctx_t *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_uniqid_module);

    if (ctx != NULL && ctx->done) {
		v->valid = 1;
		v->no_cacheable = 0;
		v->not_found = 0;
		v->data = (void*)ctx->result;
		v->len = UNIQID_SIZE;
		return NGX_OK;
	}
	v->valid = 0;
	v->no_cacheable = 0;
	v->not_found = 1;
	v->data = NULL;
	v->len = 0;
	//ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "uniqid result not found");
	return NGX_ERROR;
}
