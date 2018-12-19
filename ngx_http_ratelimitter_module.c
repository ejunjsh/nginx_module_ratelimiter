typedef struct{
    u_char   rbtree_node_data;
    ngx_queue_t queue;
    ngx_msec_t last;
    u_short len;
    u_char data[1];
} ngx_http_ratelimiter_node_t;



ngx_module_t ngx_http_ratelimiter_modulte={
    NGX_MODULE_V1,
    &ngx_http_ratelimiter_modulte_ctx,
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

static void
ngx_http_ratelimiter_rbtree_insert_value(ngx_rbtree_node_t *temp,ngx_rbtree_node_t *node,ngx_rbtree_node_t *sentinel)