
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>



#define NGX_HTTP_WAF_OFF       0
#define NGX_HTTP_WAF_BUFFERED  0x08


typedef struct {
    ngx_flag_t                   filter;
    ngx_flag_t                   store_in_file;
    size_t                       oversize;
} ngx_http_waf_filter_conf_t;


typedef struct {
    ngx_temp_file_t                  *temp_file;
    ngx_buf_t                        *buf;
} ngx_http_response_body_t;


typedef struct {
    ngx_http_response_body_t    *resbody;
    ngx_int_t			complete;
    ngx_int_t			length;
} ngx_http_waf_filter_ctx_t;



static ngx_int_t
ngx_http_waf_header_filter(ngx_http_request_t *r);

static ngx_int_t
ngx_http_waf_body_filter(ngx_http_request_t *r, ngx_chain_t *in);

static ngx_int_t
ngx_http_waf_send(ngx_http_request_t *r, ngx_http_waf_filter_ctx_t *ctx,
    ngx_chain_t *in);

static ngx_int_t
ngx_http_waf_read(ngx_http_request_t *r, ngx_chain_t *in);

static ngx_buf_t *
ngx_http_waf_process(ngx_http_request_t *r);

static void *
ngx_http_waf_filter_create_conf(ngx_conf_t *cf);

static char *
ngx_http_waf_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t
ngx_http_waf_filter_init(ngx_conf_t *cf);

static ngx_command_t  ngx_http_waf_filter_commands[] = {


    { ngx_string("waf_filter"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_filter_conf_t, filter),
      NULL },

    { ngx_string("waf_filter_oversize"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_filter_conf_t, oversize),
      NULL },

    { ngx_string("waf_response_body_in_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_filter_conf_t, store_in_file),
      NULL },


      ngx_null_command
};


static ngx_http_module_t  ngx_http_waf_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_waf_filter_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_waf_filter_create_conf,     /* create location configuration */
    ngx_http_waf_filter_merge_conf       /* merge location configuration */
};


ngx_module_t  ngx_http_waf_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_waf_filter_module_ctx,     /* module context */
    ngx_http_waf_filter_commands,        /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;



static ngx_int_t
ngx_http_waf_check_bypass(ngx_http_request_t *r)
{
    off_t                          len;
    ngx_http_waf_filter_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_waf_filter_module);
    if(conf == NULL)
	return 1;

    if (conf->filter == NGX_HTTP_WAF_OFF) {
        return 1;
    }

    /*bypass checking for oversized response body or chunked body*/
    len = r->headers_out.content_length_n;

    if (len == -1 || len > (off_t) conf->oversize) {
        return 1;
    }

    if (r->headers_out.status != NGX_HTTP_OK)
	return 1;

    if (r!=r->main)
	return 1;

    /*add more bypass checking here*/
    

    return 0;
}


static ngx_int_t
ngx_http_waf_header_filter(ngx_http_request_t *r)
{
    ngx_http_waf_filter_ctx_t   *ctx;
    ngx_int_t 			bypass=0;

    bypass=ngx_http_waf_check_bypass(r);
    
    if (bypass) {
        return ngx_http_next_header_filter(r);
    }

    /*create waf context*/ 
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_filter_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->length = r->headers_out.content_length_n;
    ngx_http_set_ctx(r, ctx, ngx_http_waf_filter_module);

    r->main_filter_need_in_memory = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                      rc;
    ngx_chain_t                    out;
    ngx_http_waf_filter_ctx_t   *ctx;


    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_waf_filter_module);

    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    if (ctx->complete) {
        return ngx_http_next_body_filter(r, in);
    }

    rc = ngx_http_waf_read(r, in);

    if (rc == NGX_AGAIN) {
        return NGX_OK;
    }

    if (rc == NGX_ERROR) {
        return ngx_http_filter_finalize_request(r,
               &ngx_http_waf_filter_module,
               NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
    }

    out.next = NULL;
    out.buf = ngx_http_waf_process(r);

    if (out.buf == NULL) {
        return ngx_http_filter_finalize_request(r,
                                              &ngx_http_waf_filter_module,
                                              NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
    }

    return ngx_http_waf_send(r, ctx, &out);
}


static ngx_int_t
ngx_http_waf_send(ngx_http_request_t *r, ngx_http_waf_filter_ctx_t *ctx,
    ngx_chain_t *in)
{
    ngx_int_t  rc;

    rc = ngx_http_next_header_filter(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return NGX_ERROR;
    }

    rc = ngx_http_next_body_filter(r, in);

    if (ctx->complete) {
        /* NGX_ERROR resets any pending data */
        return (rc == NGX_OK) ? NGX_ERROR : rc;
    }

    return rc;
}

static ngx_int_t
ngx_buf_left(ngx_buf_t *b)
{
	return b->end-b->last;
}


static ngx_http_response_body_t *
ngx_create_response_body(ngx_http_request_t *r)
{
    ngx_http_waf_filter_conf_t  *conf;
    ngx_temp_file_t		*tf;
    ngx_http_waf_filter_ctx_t   *ctx;
    ngx_http_response_body_t    *resbody;
    ngx_http_core_loc_conf_t  *clcf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_waf_filter_module);
    if(conf == NULL)
	return NULL;


    ctx = ngx_http_get_module_ctx(r, ngx_http_waf_filter_module);
    if(ctx == NULL)
	return NULL;

    resbody = ngx_pcalloc(r->pool, sizeof(ngx_http_response_body_t));
    if (resbody == NULL) {
        return NULL;
    }

    ctx->resbody = resbody;

    memset(resbody,0,sizeof(*resbody));

    if(conf->store_in_file)
    {
        tf = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
        if (tf == NULL) {
            return NULL;
        }

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        tf->file.fd = NGX_INVALID_FILE;
        tf->file.log = r->connection->log;
        tf->path = clcf->client_body_temp_path;
        tf->pool = r->pool;
        tf->warn = "a response body is buffered to a temporary file";
        tf->log_level = r->request_body_file_log_level;
        //tf->persistent = r->request_body_in_persistent_file;
        tf->persistent = 1;
        //tf->clean = r->request_body_in_clean_file;
        tf->clean = 1;

        if (r->request_body_file_group_access) {
            tf->access = 0660;
        }

        resbody->temp_file = tf;
    }
    else
    {
	resbody->buf = ngx_create_temp_buf(r->pool, ctx->length);
        if (resbody->buf == NULL) {
        	return NULL;
        }
    }

   return resbody;

}


/*write the in chain to a temp file*/
static ngx_int_t
ngx_http_waf_write_to_file(ngx_temp_file_t *temp_file,ngx_chain_t *in)
{
    ngx_int_t n;
    ngx_chain_t *cl;
    ngx_int_t complete = 0;

    n = ngx_write_chain_to_temp_file(temp_file, in);

    /* TODO: n == 0 or not complete and level event */

    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    temp_file->offset += n;

    for(cl=in;cl;cl=cl->next)
    {
        if(cl->buf)
	{
            if(cl->buf->last_buf)
             complete = 1;
            //cl->buf->pos = cl->buf->start;
            //cl->buf->last = cl->buf->start;
            cl->buf->pos = cl->buf->last;
        }
    }


    if(complete)
        return NGX_OK;
    else
        return NGX_AGAIN;
}

/*write the in chain to a memory region*/
static ngx_int_t
ngx_http_waf_write_to_memory(ngx_buf_t *resbody,ngx_chain_t *in)
{
    ngx_chain_t *cl;
    ngx_buf_t   *b;
    ngx_int_t size,left;
    ngx_int_t complete;
    

    for (cl = in; cl; cl = cl->next) {

        b = cl->buf;
        size = b->last - b->pos;
        left=ngx_buf_left(resbody);

	if(size > left)
	{
		/*to catch abnormal response,server send data bigger than content-length*/
                return NGX_ERROR;
	}

        resbody->last = ngx_cpymem(resbody->last, b->pos, size);
        b->pos += size;

        if (b->last_buf) {
            complete = 1;
        }
    }

    if(complete == 1)
	return NGX_OK;
    else
	return NGX_AGAIN;   

}

static ngx_int_t
ngx_http_waf_do_body_buffering(ngx_http_response_body_t *resbody,ngx_chain_t *in)
{
	if(resbody->temp_file)
		return ngx_http_waf_write_to_file(resbody->temp_file,in);
	else
		return ngx_http_waf_write_to_memory(resbody->buf,in);
}


static ngx_int_t
ngx_http_waf_read(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_response_body_t     *resbody;
    ngx_http_waf_filter_ctx_t  *ctx;
    ngx_int_t                  rc;

    ctx = ngx_http_get_module_ctx(r, ngx_http_waf_filter_module);

    if(ctx->complete)
	return NGX_OK;

    resbody = ctx->resbody;

    if (resbody == NULL) {
        resbody = ngx_create_response_body(r);
        if (resbody == NULL) {
        	return NGX_ERROR;
        }
	ctx->resbody = resbody;
    }

    rc = ngx_http_waf_do_body_buffering(ctx->resbody,in);

    r->connection->buffered |= NGX_HTTP_WAF_BUFFERED;

    return rc;
}


static ngx_buf_t *
ngx_http_waf_process(ngx_http_request_t *r)
{
    ngx_http_waf_filter_ctx_t   *ctx;
    ngx_buf_t *b;

    r->connection->buffered &= ~NGX_HTTP_WAF_BUFFERED;
    ctx = ngx_http_get_module_ctx(r, ngx_http_waf_filter_module);

    b=ctx->resbody->buf;

    if(b == NULL)
    {
        b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
        if (b == NULL) {
            return NULL;
        }
        b->file = &ctx->resbody->temp_file->file;
        b->in_file = 1;
        b->temp_file = 1;
        b->last_buf = 1;
        b->last_in_chain = 1;
        b->file_last = ctx->resbody->temp_file->offset;
    }


    b->last_buf = 1;
    return b;
}



static void *
ngx_http_waf_filter_create_conf(ngx_conf_t *cf)
{
    ngx_http_waf_filter_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_filter_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->filter = NGX_CONF_UNSET_UINT;
    conf->store_in_file = NGX_CONF_UNSET_UINT;
    conf->oversize = NGX_CONF_UNSET_SIZE;

    return conf;
}


static char *
ngx_http_waf_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_waf_filter_conf_t *prev = parent;
    ngx_http_waf_filter_conf_t *conf = child;

    ngx_conf_merge_value(conf->filter,prev->filter,0);
    ngx_conf_merge_value(conf->store_in_file,prev->store_in_file,0);
    ngx_conf_merge_size_value(conf->oversize, prev->oversize,
                              512 * 1024);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_waf_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_waf_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_waf_body_filter;

    return NGX_OK;
}
