#include <netdb.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <ngx_core.h>
#include <sys/socket.h>
//#include "uniqid_udp.h"
#include "uniqid_request.h"

int
ngx_http_replace_header(ngx_str_t *key, ngx_str_t *value, ngx_http_request_t *r)
{
    u_char           ch;
    ngx_uint_t       i, n;
    ngx_table_elt_t *header;
	ngx_list_part_t *part = &r->headers_in.headers.part;

    header = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        for (n = 0; n < key->len && n < header[i].key.len; n++) {
            ch = header[i].key.data[n];

            if (ch >= 'A' && ch <= 'Z') {
                ch |= 0x20;

            //} else if (ch == '-') {
            //    ch = '_';
            }

            if (key->data[n] != ch) {
                break;
            }
        }

        if (n == key->len && n == header[i].key.len) {
			if (header[i].value.len == value->len) {
				memcpy(header[i].value.data, value->data, value->len);
				return 0;
			}
            break;
        }
    }

    return -1;
}

ngx_int_t
ngx_http_variable_header_external(ngx_http_variable_value_t *v, ngx_str_t *var, ngx_list_part_t *part)
{
    u_char            ch;
    ngx_uint_t        i, n;
    ngx_table_elt_t  *header;

    header = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        for (n = 0; n < var->len && n < header[i].key.len; n++) {
            ch = header[i].key.data[n];

            if (ch >= 'A' && ch <= 'Z') {
                ch |= 0x20;

            //} else if (ch == '-') {
            //    ch = '_';
            }

            if (var->data[n] != ch) {
                break;
            }
        }

        if (n == var->len && n == header[i].key.len) {
            v->len = header[i].value.len;
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;
            v->data = header[i].value.data;

            return NGX_OK;
        }
    }

    v->not_found = 1;

    return NGX_OK;
}

uniqid *uniqid_request_get_uid(ngx_http_request_t *r)
{
	uniqid *uid;
	ngx_str_t uid_header = ngx_string("uniqid");
	ngx_http_variable_value_t v = ngx_http_variable_null_value;

	ngx_http_variable_header_external(&v, &uid_header, &r->headers_in.headers.part);
	if (v.valid == 1 && v.len > 0) {
		uid = ngx_pnalloc(r->pool, v.len);
		if (uid == NULL) {
			return NULL;
		}
		memcpy(uid, v.data, v.len);
		return uid;
	}
	return NULL;
}

int get_local_ip(char *buf)
{
	struct ifaddrs *ifaddr, *ifa;
	int family;
	void *sa;
	//char addr[INET_ADDRSTRLEN];

	if (getifaddrs(&ifaddr) == -1) {
		//perror("getifaddrs");
		return -1;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;

		family = ifa->ifa_addr->sa_family;

		if (family == AF_INET && !strncmp(ifa->ifa_name, "eth0", 4)) {
			sa = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
			inet_ntop(AF_INET, sa, buf, INET_ADDRSTRLEN);
			//printf("%s IPV4 Address %s\n", ifa->ifa_name, addr);
			freeifaddrs(ifaddr);
			return 0;
		}
	}

	freeifaddrs(ifaddr);
	return -1;
}

pid_t uniqid_request_get_pid()
{
	return ngx_pid;
}

uint64_t uniqid_request_get_timems()
{
	uint64_t timems;
	ngx_time_t  *tp;
	tp = ngx_timeofday();
	timems = tp->sec * 1000 + tp->msec;
	return timems;
}

char *uniqid_request_get_localip(ngx_http_request_t *r)
{
	ngx_str_t s;
	char *addr;

	addr = ngx_pnalloc(r->pool, NGX_SOCKADDR_STRLEN);
	if (addr == NULL) {
		return NULL;
	}
	
	s.len = NGX_SOCKADDR_STRLEN;
	s.data = addr;

	if (ngx_connection_local_sockaddr(r->connection, &s, 0) != NGX_OK) {
		return NULL;
	}

	return addr;
}

uint16_t uniqid_request_get_localport(ngx_http_request_t *r)
{
	uint16_t             port;
	struct sockaddr_in  *sin;
#if (NGX_HAVE_INET6)
	struct sockaddr_in6 *sin6;
#endif
	if (ngx_connection_local_sockaddr(r->connection, NULL, 0) != NGX_OK) {
		return 0;
	}

	switch (r->connection->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *) r->connection->local_sockaddr;
			port = ntohs(sin6->sin6_port);
			break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
		case AF_UNIX:
			port = 0;
			break;
#endif

		default: /* AF_INET */
			sin = (struct sockaddr_in *) r->connection->local_sockaddr;
			port = ntohs(sin->sin_port);
			break;
	}

	return port;
}

char *uniqid_request_get_peerip_real(ngx_http_request_t *r)
{
	char *ip;
	int size = r->connection->addr_text.len;
	//TODO: ipv6
	ip = ngx_pnalloc(r->pool, 16);
	if (ip == NULL) {
		return NULL;
	}
	
	memset(ip, 0, 16);
	memcpy(ip, r->connection->addr_text.data, (size < 16) ? size : 16);
	//ip[15] = 0;
	return ip;
}

char *uniqid_request_get_peerip_from_header(ngx_http_request_t *r)
{
	int alen;
	char *ip, *pos;
	ngx_table_elt_t  **h;

	if (r->headers_in.x_forwarded_for.nelts == 0) {
		return NULL;
	}

	ip = ngx_pnalloc(r->pool, 16);
	if (ip == NULL) {
		return NULL;
	}
	
	h = r->headers_in.x_forwarded_for.elts;

	alen = h[0]->value.len;
	pos = strchr((char *)h[0]->value.data, ' '); /* get proxy ip */
	if (pos) { //deal multi ip
		pos++;
		alen = alen - (pos - (char *)h[0]->value.data);
		if (alen > 15) {
			return NULL;
		}
	} else {
		pos = h[0]->value.data;
	}

	strncpy(ip, pos, 16);
	ip[15] = '\0';

	return ip;
}

char *uniqid_request_get_peerip(ngx_http_request_t *r)
{
	char *ip;
	if (ip = uniqid_request_get_peerip_from_header(r)) {
		return ip;
	} else {
		return uniqid_request_get_peerip_real(r);
	}
}

uint16_t uniqid_request_get_peerport(ngx_http_request_t *r)
{
	uint16_t port;
	struct sockaddr_in *sin;
	switch (r->connection->sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
			port = ntohs(sin6->sin6_port);
			break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
		case AF_UNIX:
			port = 0;
			break;
#endif

		default: /* AF_INET */
			sin = (struct sockaddr_in *) r->connection->sockaddr;
			port = ntohs(sin->sin_port);
			break;
	}

	return port;
}

ngx_str_t ngx_http_uniqid_get_rawheader(ngx_http_request_t *r)
{
	u_char *data;
	ngx_str_t header;
	int count = 0;
	
	header.len = r->header_in->last - r->header_in->start;

	data = ngx_pcalloc(r->pool, header.len);
	if (data == NULL) {
		header.data = NULL;
		header.len = 0;
		return header;
	}

	memcpy(data, r->header_in->start, header.len);

	while (count < header.len) {
		if (data[count] == 0) {
			if (data[count + 1] == ' ') {
				data[count] = ':';
			} else if (data[count + 1] == '\n') {
				data[count] = '\r';
			}
		}
		count++;
	}
	

	header.data = data;

	return header;
}

uniqid *uniqid_request_generate_uid(char *ip)
{
	//char *ip;
	pid_t pid;
	uintptr_t time_ms;

	//ip = uniqid_request_get_localip(r);
	time_ms = uniqid_request_get_timems();
	pid = uniqid_request_get_pid();

	return uniqid_generate_uid(UNIQID_MAGIC, ip, time_ms, pid);
}

uint16_t uniqid_request_uid_hash(uniqid *id, int len)
{
	//uintptr_t time_ms;
	uint16_t rand = id[0][26] + id[0][27] + id[0][28] + id[0][29];

	fprintf(stderr, "hash rand is %u\n", rand);
	return rand % len;
}
