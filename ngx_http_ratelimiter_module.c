#include "ngx_core.h"
#include "ngx_string.h"
#include "ngx_buf.h"
#include "ngx_module.h"
#include "ngx_conf_file.h"
#include "ngx_http.h" 
#include "ngx_http_request.h"
#include "ngx_http_config.h"
#include "ngx_http_core_module.h"

typedef struct{
    u_char   rbtree_node_data;
    ngx_queue_t queue;
    ngx_msec_t last;
    u_short len;
    u_char data[1];
} ngx_http_ratelimiter_node_t;

typedef struct{
    ngx_rbtree_t rbtree;
    ngx_rbtree_node_t sentinel;
    ngx_queue_t queue;
} ngx_http_ratelimiter_shm_t;

typedef struct{
    ssize_t shmsize;
    ngx_int_t interval;
    ngx_slab_pool_t *shpool;
    ngx_http_ratelimiter_shm_t *sh;
} ngx_http_ratelimiter_conf_t;

ngx_module_t ngx_http_ratelimiter_module;

static ngx_int_t
ngx_http_ratelimiter_lookup(ngx_http_request_t *r, ngx_http_ratelimiter_conf_t *conf, ngx_uint_t hash, u_char* data, size_t len);

static char *
ngx_http_ratelimiter_createmem(ngx_conf_t *cf, ngx_command_t *cmd, void* conf);

static void
ngx_http_ratelimiter_expire(ngx_http_request_t *r,ngx_http_ratelimiter_conf_t *conf);

static ngx_int_t
ngx_http_ratelimiter_shm_init(ngx_shm_zone_t *shm_zone, void *data);

static ngx_int_t
ngx_http_ratelimiter_handler(ngx_http_request_t *r);

static ngx_int_t
ngx_http_ratelimiter_init(ngx_conf_t *cf);

static void *
ngx_http_ratelimiter_create_main_conf(ngx_conf_t *cf);



static ngx_http_module_t ngx_http_ratelimiter_module_ctx =
{
    NULL, /* preconfiguration */
    ngx_http_ratelimiter_init, /* postconfiguration */
    ngx_http_ratelimiter_create_main_conf, /* create main configuration */
    NULL, /* init main configuration */
    NULL, /* create server configuration */
    NULL, /* merge server configuration */
    NULL, /* create location configuration */
    NULL /* merge location configuration */
};

static ngx_command_t ngx_http_ratelimiter_commands[] = {
    { 
        ngx_string("ratelimiter"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2, 
        ngx_http_ratelimiter_createmem,
        0,
        0,
        NULL 
    },
    ngx_null_command
};

ngx_module_t ngx_http_ratelimiter_module={
    NGX_MODULE_V1,
    &ngx_http_ratelimiter_module_ctx,
    ngx_http_ratelimiter_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

static void
ngx_http_ratelimiter_rbtree_insert_value(ngx_rbtree_node_t *temp,ngx_rbtree_node_t *node,ngx_rbtree_node_t *sentinel);

static ngx_int_t
ngx_http_ratelimiter_lookup(ngx_http_request_t *r, ngx_http_ratelimiter_conf_t *conf, ngx_uint_t hash, u_char* data, size_t len);

static void
ngx_http_ratelimiter_expire(ngx_http_request_t *r,ngx_http_ratelimiter_conf_t *conf) ;

static char *
ngx_http_ratelimiter_createmem(ngx_conf_t *cf, ngx_command_t* cmd, void* conf);

static ngx_int_t
ngx_http_ratelimiter_shm_init(ngx_shm_zone_t *shm_zone, void *data);

static ngx_int_t
ngx_http_ratelimiter_handler(ngx_http_request_t *r) {
    size_t len;
    uint32_t hash;
    ngx_int_t rc;
    ngx_http_ratelimiter_conf_t *conf;
    conf = ngx_http_get_module_main_conf(r, ngx_http_ratelimiter_module); 
    rc = NGX_DECLINED;
    if (conf->interval == -1)
        return rc;
    len = r->connection->addr_text.len + r->uri.len;
    u_char* data = ngx_palloc(r->pool, len); 
    ngx_memcpy(data, r->uri.data, r->uri.len); 
    ngx_memcpy(data+r->uri.len, r->connection->addr_text.data, r->connection->addr_text.len); 
    hash = ngx_crc32_short(data, len);
    ngx_shmtx_lock(&conf->shpool->mutex); 
    rc = ngx_http_ratelimiter_lookup(r, conf, hash, data, len); 
    ngx_shmtx_unlock(&conf->shpool->mutex); 
    return rc;
}

static ngx_int_t
ngx_http_ratelimiter_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module); 
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers); 
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_ratelimiter_handler;
    return NGX_OK;
}

static void *
ngx_http_ratelimiter_create_main_conf(ngx_conf_t *cf) {
    ngx_http_ratelimiter_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ratelimiter_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->interval = -1;
    conf->shmsize = -1;
    return conf;
}

static void
ngx_http_ratelimiter_rbtree_insert_value(ngx_rbtree_node_t *temp,ngx_rbtree_node_t *node,ngx_rbtree_node_t *sentinel){
    ngx_rbtree_node_t **p;
    ngx_http_ratelimiter_node_t* lrn, *lrnt;
    for ( ;; ) {
        if (node->key < temp->key) {
            p = &temp->left;
        } 
        else if (node->key > temp->key) {
            p = &temp->right;
        } else {
            lrn = (ngx_http_ratelimiter_node_t*) &node->data; 
            lrnt = (ngx_http_ratelimiter_node_t*) &temp->data;
            p = (ngx_memn2cmp(lrn->data, lrnt->data, lrn->len, lrnt->len) < 0)? &temp->left : &temp->right; 
        }

        if (*p == sentinel) {
            break;
        }

    temp = *p;

    }
    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);

}

static ngx_int_t
ngx_http_ratelimiter_lookup(ngx_http_request_t *r, ngx_http_ratelimiter_conf_t *conf, ngx_uint_t hash, u_char* data, size_t len){
    size_t size;
    ngx_int_t rc;
    ngx_time_t *tp;
    ngx_msec_t now;
    ngx_msec_int_t ms;
    ngx_rbtree_node_t *node, *sentinel; 
    ngx_http_ratelimiter_node_t *lr;

    tp = ngx_timeofday();
    now = (ngx_msec_t) (tp->sec * 1000 + tp->msec); 
    node = conf->sh->rbtree.root;
    sentinel = conf->sh->rbtree.sentinel; 
    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }
        if (hash > node->key) {
            node = node->right;
            continue;
        }

        lr = (ngx_http_ratelimiter_node_t *) &node->data;

        rc = ngx_memn2cmp(data, lr->data, len, (size_t) lr->len); 
        
        if (rc == 0) {
            ms = (ngx_msec_int_t) (now - lr->last); 
            if (ms > conf->interval) {
                lr->last = now;
                ngx_queue_remove(&lr->queue);
                ngx_queue_insert_head(&conf->sh->queue, &lr->queue); 
                return NGX_DECLINED;
            } 
            else {
                lr->last = now;
                return NGX_HTTP_FORBIDDEN;
            }
        }
        node = (rc < 0) ? node->left : node->right; 
    }

    size = offsetof(ngx_rbtree_node_t, data) + offsetof(ngx_http_ratelimiter_node_t, data) + len;

    ngx_http_ratelimiter_expire(r, conf);

    node = ngx_slab_alloc_locked(conf->shpool, size); 

    if (node == NULL) {
        return NGX_ERROR;
    }

    node->key = hash;
    lr = (ngx_http_ratelimiter_node_t *) &node->data;
    lr->last = now;
    lr->len = (u_char) len;
    ngx_memcpy(lr->data, data, len);

    ngx_rbtree_insert(&conf->sh->rbtree, node); 
    ngx_queue_insert_head(&conf->sh->queue, &lr->queue); 
    
    return NGX_DECLINED;
}

static void
ngx_http_ratelimiter_expire(ngx_http_request_t *r,ngx_http_ratelimiter_conf_t *conf) {
    ngx_time_t *tp;
    ngx_msec_t now;
    ngx_queue_t *q;
    ngx_msec_int_t ms;
    ngx_rbtree_node_t *node;
    ngx_http_ratelimiter_node_t *lr;

    tp = ngx_timeofday();
    now = (ngx_msec_t) (tp->sec * 1000 + tp->msec); 

    while (1) {
        if (ngx_queue_empty(&conf->sh->queue)) {
            return;
        }

        q = ngx_queue_last(&conf->sh->queue);

        lr = ngx_queue_data(q, ngx_http_ratelimiter_node_t, queue);

        node = (ngx_rbtree_node_t*)((u_char*)lr-offsetof(ngx_rbtree_node_t,data));

        ms = (ngx_msec_int_t) (now - lr->last); 
        
        if (ms < conf->interval) {
            return;
        }
        ngx_queue_remove(q);
        ngx_rbtree_delete(&conf->sh->rbtree, node); 
        ngx_slab_free_locked(conf->shpool, node); 
    }
}



static char *
ngx_http_ratelimiter_createmem(ngx_conf_t *cf, ngx_command_t* cmd, void* conf) {
    ngx_str_t *value;
    ngx_shm_zone_t *shm_zone;
    ngx_http_ratelimiter_conf_t* mconf = (ngx_http_ratelimiter_conf_t* )conf;
    ngx_str_t name = ngx_string("ratelimiter_shm"); 
    value = cf->args->elts;
    mconf->interval = ngx_atoi(value[1].data, value[1].len); 
    if (mconf->interval == NGX_ERROR || mconf->interval == 0) {
        mconf->interval = -1;
        return "invalid value";
    }

    mconf->shmsize = ngx_parse_size(&value[2]); 
    if (mconf->shmsize == (ssize_t) NGX_ERROR || mconf->shmsize == 0) {
        mconf->interval = -1;
        return "invalid value";
    }

    shm_zone = ngx_shared_memory_add(cf, &name, mconf->shmsize, &ngx_http_ratelimiter_module); 
    if (shm_zone == NULL) {
        mconf->interval = -1;
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_ratelimiter_shm_init; 
    shm_zone->data = mconf;
    return NGX_CONF_OK;
}



static ngx_int_t
ngx_http_ratelimiter_shm_init(ngx_shm_zone_t *shm_zone, void *data) {
    ngx_http_ratelimiter_conf_t *conf;
    ngx_http_ratelimiter_conf_t *oconf = data;
    conf = (ngx_http_ratelimiter_conf_t *)shm_zone->data;

    if (oconf) {
        conf->sh = oconf->sh;
        conf->shpool = oconf->shpool; 
        return NGX_OK;
    }

    conf->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    conf->sh = ngx_slab_alloc(conf->shpool, sizeof(ngx_http_ratelimiter_shm_t)); 
    if (conf->sh == NULL) {
        return NGX_ERROR;
    }

    conf->shpool->data = conf->sh;
    ngx_rbtree_init(&conf->sh->rbtree, &conf->sh->sentinel, ngx_http_ratelimiter_rbtree_insert_value);

    ngx_queue_init(&conf->sh->queue);

    size_t len = sizeof(" in ratelimiter \"\"") + shm_zone->shm.name.len;
    conf->shpool->log_ctx = ngx_slab_alloc(conf->shpool, len);
    if (conf->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(conf->shpool->log_ctx, " in ratelimiter \"%V\"%Z", &shm_zone->shm.name); 
    
    return NGX_OK;
}


