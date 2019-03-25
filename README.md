# nginx_module_ratelimiter

a module can limit the duplicate request amount in some interval

## precondition

download the nginx source code

## configure

    # git clone this repo
    # go to the nginx source code folder
    # specify this repo path of your system
    ./configure --add-module=/home/sky/code/nginx_module_ratelimiter

## build

    make && make install

## nginx.conf

    # add below ratelimiter option into http section:ratelimiter [interval(ms)] [slab size(m/k/g)]
    http {
        ....
        ratelimiter 500 10m; 
        ....
    }
    # interval means only allow one same request during this interval(or a same request will expire after this interval)
    # if another same request is incoming,the nginx will drop this request and return 403
    # slab size represets the total memory that store the all unexpired requests, 
    # if this memory is run out, the nginx will drop the following requests and return 403.
    # if the requests of slab memory expire, the memory will be released and treats the new requests again.

## test

    ./nginx

open http://localhost , you will see the `403 Forbidden` in the browser when you refresh the same page many times during 500ms
